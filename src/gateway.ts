import { existsSync, lstatSync, readdirSync, readFileSync, realpathSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname, isAbsolute, relative, resolve, sep } from 'node:path';
import { z } from 'zod';
import type { Backend } from './backends/types.js';
import type { CanaryDetector } from './canary.js';
import type { PolicyEngine } from './policy.js';
import type { Trace } from './trace.js';
import type { ToolCall, ToolResult, Violation, ViolationType } from './types.js';

export interface HttpRequest {
	url: string;
	method: string;
	headers: Record<string, string>;
	body?: string;
}

export interface HttpResponse {
	status: number;
	body: string;
}

export type Fetcher = (request: HttpRequest) => Promise<HttpResponse>;

/** Default fetcher: records the request and never touches the network. */
export const stubFetcher: Fetcher = async (request) => ({
	status: 200,
	body: `stubbed ${request.method} ${new URL(request.url).host}`,
});

export const liveFetcher: Fetcher = async ({ url, method, headers, body }) => {
	const response = await fetch(url, { method, headers, body, redirect: 'manual' });
	return { status: response.status, body: await response.text() };
};

const argSchemas = {
	read_file: z.object({ path: z.string().min(1) }).strict(),
	write_file: z.object({ path: z.string().min(1), content: z.string() }).strict(),
	list_dir: z.object({ path: z.string().default('.') }).strict(),
	run_command: z.object({ command: z.string().min(1) }).strict(),
	http_request: z
		.object({
			url: z.string().min(1),
			method: z.enum(['GET', 'POST', 'PUT', 'PATCH', 'DELETE']).default('GET'),
			headers: z.record(z.string()).default({}),
			body: z.string().optional(),
		})
		.strict(),
} as const;

type ToolName = keyof typeof argSchemas;

export interface GatewayOptions {
	workspace: string;
	policy: PolicyEngine;
	backend: Backend;
	detector: CanaryDetector;
	trace: Trace;
	fetcher?: Fetcher;
}

class Denied extends Error {
	constructor(
		readonly type: ViolationType,
		readonly detail: string,
		readonly rule?: string,
	) {
		super(detail);
	}
}

/**
 * The single policy enforcement point. Agents never touch the filesystem,
 * network or shell directly; every action is a tool call that passes through
 * here, is checked against policy and DLP, and is written to the trace.
 */
export class ToolGateway {
	readonly violations: Violation[] = [];
	private calls = 0;
	private readonly workspace: string;
	private readonly fetcher: Fetcher;

	constructor(private readonly options: GatewayOptions) {
		this.workspace = realpathSync(options.workspace);
		this.fetcher = options.fetcher ?? stubFetcher;
	}

	get toolCalls(): number {
		return this.calls;
	}

	async call(call: ToolCall): Promise<ToolResult> {
		const { trace, policy } = this.options;
		this.calls++;
		trace.emit('tool_call', { seq: this.calls, tool: call.tool, args: call.args });

		try {
			if (this.calls > policy.policy.limits.maxToolCalls) {
				throw new Denied(
					'limit_exceeded',
					`tool call budget of ${policy.policy.limits.maxToolCalls} exhausted`,
					'limits.maxToolCalls',
				);
			}
			const toolDecision = policy.checkTool(call.tool);
			if (!toolDecision.allow) {
				throw new Denied('tool_not_allowed', toolDecision.reason, toolDecision.rule);
			}
			if (!(call.tool in argSchemas)) {
				throw new Denied('tool_not_allowed', `unknown tool "${call.tool}"`);
			}
			const tool = call.tool as ToolName;
			const parsed = argSchemas[tool].safeParse(call.args);
			if (!parsed.success) {
				throw new Denied('invalid_arguments', parsed.error.issues.map((i) => i.message).join('; '));
			}
			this.checkDlp(tool, parsed.data);

			const output = truncate(
				await this.execute(tool, parsed.data),
				policy.policy.limits.maxOutputBytes,
			);
			trace.emit('tool_result', { tool, ok: true, output });
			return { ok: true, output };
		} catch (error) {
			if (error instanceof Denied) {
				this.recordViolation({
					type: error.type,
					blocked: true,
					detail: error.detail,
					tool: call.tool,
					rule: error.rule,
				});
				trace.emit('tool_result', { tool: call.tool, ok: false, denied: true, error: error.detail });
				return { ok: false, denied: true, error: `Denied by policy: ${error.detail}` };
			}
			const message = error instanceof Error ? error.message : String(error);
			trace.emit('tool_result', { tool: call.tool, ok: false, denied: false, error: message });
			return { ok: false, denied: false, error: message };
		}
	}

	recordViolation(violation: Violation): void {
		this.violations.push(violation);
		this.options.trace.emit('violation', { ...violation });
	}

	private checkDlp(tool: ToolName, args: unknown): void {
		if (!this.options.policy.policy.dlp.scanTools.includes(tool)) return;
		const findings = this.options.detector.scan(JSON.stringify(args));
		if (findings.length > 0) {
			const what = findings.map((f) => `${f.name} (${f.encoding})`).join(', ');
			throw new Denied('secret_egress', `arguments contain canary secret: ${what}`, 'dlp.scanTools');
		}
	}

	private async execute(tool: ToolName, args: any): Promise<string> {
		switch (tool) {
			case 'read_file': {
				const file = this.resolvePath(args.path, 'read');
				return readFileSync(file, 'utf8');
			}
			case 'write_file': {
				const file = this.resolvePath(args.path, 'write');
				mkdirSync(dirname(file), { recursive: true });
				writeFileSync(file, args.content);
				return `wrote ${Buffer.byteLength(args.content)} bytes`;
			}
			case 'list_dir': {
				const dir = this.resolvePath(args.path, 'read');
				return readdirSync(dir, { withFileTypes: true })
					.map((d) => (d.isDirectory() ? `${d.name}/` : d.name))
					.sort()
					.join('\n');
			}
			case 'run_command': {
				const { backend, policy } = this.options;
				if (!backend.supportsCommands) {
					throw new Denied(
						'command_unsupported',
						`backend "${backend.name}" does not execute commands`,
					);
				}
				const result = await backend.exec(args.command, policy.policy.limits.commandTimeoutMs);
				return JSON.stringify(result);
			}
			case 'http_request': {
				const decision = this.options.policy.checkUrl(args.url);
				if (!decision.allow) throw new Denied('network_denied', decision.reason, decision.rule);
				const response = await this.fetcher({
					url: args.url,
					method: args.method,
					headers: args.headers,
					body: args.body,
				});
				return JSON.stringify(response);
			}
		}
	}

	/**
	 * Resolve an agent-supplied path to an absolute host path inside the
	 * workspace, rejecting traversal and symlinks that point outside it, then
	 * apply the filesystem policy to the workspace-relative path.
	 */
	private resolvePath(input: string, mode: 'read' | 'write'): string {
		const candidate = isAbsolute(input) ? resolve(input) : resolve(this.workspace, input);
		const lexical = relative(this.workspace, candidate);
		if (lexical.startsWith('..') || isAbsolute(lexical)) {
			throw new Denied('path_escape', `"${input}" resolves outside the workspace`);
		}

		// Follow symlinks on the longest existing prefix so a link inside the
		// workspace cannot be used to reach files outside it.
		let existing = candidate;
		while (!existsSync(existing)) existing = dirname(existing);
		const real = realpathSync(existing);
		if (real !== this.workspace && !real.startsWith(this.workspace + sep)) {
			throw new Denied('path_escape', `"${input}" follows a symlink outside the workspace`);
		}
		if (mode === 'write' && existsSync(candidate) && lstatSync(candidate).isSymbolicLink()) {
			throw new Denied('path_escape', `"${input}" is a symlink; writing through links is not allowed`);
		}

		const rel = lexical.split(sep).join('/');
		const decision = this.options.policy.checkPath(rel, mode);
		if (!decision.allow) throw new Denied('path_denied', decision.reason, decision.rule);
		return candidate;
	}
}

function truncate(text: string, maxBytes: number): string {
	if (Buffer.byteLength(text) <= maxBytes) return text;
	return Buffer.from(text).subarray(0, maxBytes).toString('utf8') + '\n[truncated]';
}
