import { readFileSync } from 'node:fs';
import picomatch from 'picomatch';
import { parse as parseYaml } from 'yaml';
import { z } from 'zod';

export const TOOL_NAMES = [
	'read_file',
	'write_file',
	'list_dir',
	'run_command',
	'http_request',
] as const;

export const PolicySchema = z
	.object({
		version: z.literal(1),
		tools: z
			.object({
				allow: z.array(z.string()).default([]),
			})
			.strict()
			.default({}),
		filesystem: z
			.object({
				/**
				 * Globs relative to the workspace root. Deny always wins over read/write.
				 * The root directory itself is "."; "**" does not include it.
				 */
				read: z.array(z.string()).default([]),
				write: z.array(z.string()).default([]),
				deny: z.array(z.string()).default([]),
			})
			.strict()
			.default({}),
		network: z
			.object({
				/** Exact hostnames, or "*.example.com" for subdomains. Empty means no egress. */
				allowHosts: z.array(z.string()).default([]),
			})
			.strict()
			.default({}),
		limits: z
			.object({
				maxToolCalls: z.number().int().positive().default(50),
				commandTimeoutMs: z.number().int().positive().default(10_000),
				maxOutputBytes: z.number().int().positive().default(64 * 1024),
			})
			.strict()
			.default({}),
		dlp: z
			.object({
				/** Block any call to these tools whose arguments contain a canary secret. */
				scanTools: z
					.array(z.enum(TOOL_NAMES))
					.default(['http_request', 'run_command', 'write_file']),
			})
			.strict()
			.default({}),
	})
	.strict();

export type PolicyInput = z.input<typeof PolicySchema>;
export type Policy = z.output<typeof PolicySchema>;

export type Decision =
	| { allow: true }
	| { allow: false; rule: string; reason: string };

const ALLOW: Decision = { allow: true };

export function parsePolicy(input: unknown): Policy {
	return PolicySchema.parse(input);
}

export function loadPolicyFile(path: string): Policy {
	return parsePolicy(parseYaml(readFileSync(path, 'utf8')));
}

export class PolicyEngine {
	private readonly readMatch: Matcher;
	private readonly writeMatch: Matcher;
	private readonly denyMatch: Matcher;

	constructor(readonly policy: Policy) {
		const fs = policy.filesystem;
		this.readMatch = compileGlobs(fs.read);
		this.writeMatch = compileGlobs(fs.write);
		this.denyMatch = compileGlobs(fs.deny);
	}

	checkTool(name: string): Decision {
		if (this.policy.tools.allow.includes(name)) return ALLOW;
		return {
			allow: false,
			rule: 'tools.allow',
			reason: `tool "${name}" is not in the allow list`,
		};
	}

	/** `relPath` must already be normalised, POSIX-style and inside the workspace. */
	checkPath(relPath: string, mode: 'read' | 'write'): Decision {
		const target = relPath === '' ? '.' : relPath;
		if (this.denyMatch(target)) {
			return {
				allow: false,
				rule: 'filesystem.deny',
				reason: `"${target}" matches a deny rule`,
			};
		}
		const matcher = mode === 'read' ? this.readMatch : this.writeMatch;
		if (matcher(target)) return ALLOW;
		return {
			allow: false,
			rule: `filesystem.${mode}`,
			reason: `"${target}" is not covered by filesystem.${mode}`,
		};
	}

	checkUrl(rawUrl: string): Decision {
		let url: URL;
		try {
			url = new URL(rawUrl);
		} catch {
			return { allow: false, rule: 'network', reason: 'invalid URL' };
		}
		if (url.protocol !== 'https:' && url.protocol !== 'http:') {
			return {
				allow: false,
				rule: 'network',
				reason: `scheme "${url.protocol}" is not allowed`,
			};
		}
		if (url.username || url.password) {
			return {
				allow: false,
				rule: 'network',
				reason: 'credentials in URL are not allowed',
			};
		}
		const host = url.hostname.toLowerCase();
		const allowed = this.policy.network.allowHosts.some((pattern) =>
			hostMatches(host, pattern.toLowerCase()),
		);
		if (allowed) return ALLOW;
		return {
			allow: false,
			rule: 'network.allowHosts',
			reason: `host "${host}" is not in the allow list`,
		};
	}
}

type Matcher = (path: string) => boolean;

function compileGlobs(globs: string[]): Matcher {
	if (globs.length === 0) return () => false;
	const match = picomatch(globs, { dot: true });
	return (path) => match(path);
}

function hostMatches(host: string, pattern: string): boolean {
	if (pattern.startsWith('*.')) {
		const suffix = pattern.slice(1); // ".example.com"
		return host.endsWith(suffix) && host.length > suffix.length;
	}
	return host === pattern;
}
