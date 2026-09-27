import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { LocalBackend } from '../src/backends/local.js';
import { CanaryDetector, createCanaries, renderDotenv } from '../src/canary.js';
import { type HttpRequest, ToolGateway } from '../src/gateway.js';
import { type PolicyInput, PolicyEngine, parsePolicy } from '../src/policy.js';
import { Trace } from '../src/trace.js';

const canaries = createCanaries();
const detector = new CanaryDetector(canaries);
let workspace: string;
let outside: string;
let requests: HttpRequest[];

beforeEach(() => {
	workspace = mkdtempSync(join(tmpdir(), 'gw-ws-'));
	outside = mkdtempSync(join(tmpdir(), 'gw-outside-'));
	writeFileSync(join(outside, 'secret.txt'), 'outside the workspace');
	writeFileSync(join(workspace, 'README.md'), '# hello\n');
	writeFileSync(join(workspace, '.env'), renderDotenv(canaries));
	mkdirSync(join(workspace, 'out'));
	requests = [];
});

afterEach(() => {
	rmSync(workspace, { recursive: true, force: true });
	rmSync(outside, { recursive: true, force: true });
});

function gateway(policy: Partial<PolicyInput> = {}, traceFile?: string) {
	const trace = new Trace('test-run', detector, traceFile);
	const gw = new ToolGateway({
		workspace,
		policy: new PolicyEngine(
			parsePolicy({
				version: 1,
				tools: { allow: ['read_file', 'write_file', 'list_dir', 'http_request', 'run_command'] },
				filesystem: { read: ['.', '**'], write: ['out/**'], deny: ['.env'] },
				network: { allowHosts: ['api.github.com'] },
				...policy,
			}),
		),
		backend: new LocalBackend(),
		detector,
		trace,
		fetcher: async (request) => {
			requests.push(request);
			return { status: 200, body: 'ok' };
		},
	});
	return { gw, trace };
}

describe('filesystem tools', () => {
	it('reads allowed files and lists the workspace', async () => {
		const { gw } = gateway();
		expect(await gw.call({ tool: 'read_file', args: { path: 'README.md' } })).toEqual({
			ok: true,
			output: '# hello\n',
		});
		const listing = await gw.call({ tool: 'list_dir', args: {} });
		expect(listing.ok && listing.output.split('\n')).toEqual(['.env', 'README.md', 'out/']);
		expect(gw.violations).toEqual([]);
	});

	it.each([
		['relative traversal', '../secret.txt'],
		['absolute path', '/etc/passwd'],
		['nested traversal', 'out/../../x'],
	])('blocks %s', async (_, path) => {
		const { gw } = gateway();
		const result = await gw.call({ tool: 'read_file', args: { path } });
		expect(result).toMatchObject({ ok: false, denied: true });
		expect(gw.violations[0]?.type).toBe('path_escape');
	});

	it('blocks symlinks that point outside the workspace', async () => {
		symlinkSync(outside, join(workspace, 'link'));
		const { gw } = gateway();
		const result = await gw.call({ tool: 'read_file', args: { path: 'link/secret.txt' } });
		expect(result).toMatchObject({ ok: false, denied: true });
		expect(gw.violations[0]?.type).toBe('path_escape');
	});

	it('refuses to write through a symlink even inside the write area', async () => {
		symlinkSync(join(outside, 'secret.txt'), join(workspace, 'out', 'report.md'));
		const { gw } = gateway();
		await gw.call({ tool: 'write_file', args: { path: 'out/report.md', content: 'x' } });
		expect(gw.violations[0]?.type).toBe('path_escape');
		expect(readFileSync(join(outside, 'secret.txt'), 'utf8')).toBe('outside the workspace');
	});

	it('applies deny and write rules', async () => {
		const { gw } = gateway();
		await gw.call({ tool: 'read_file', args: { path: '.env' } });
		await gw.call({ tool: 'write_file', args: { path: 'README.md', content: 'x' } });
		const ok = await gw.call({ tool: 'write_file', args: { path: 'out/a/b.md', content: 'x' } });
		expect(gw.violations.map((v) => v.type)).toEqual(['path_denied', 'path_denied']);
		expect(ok.ok).toBe(true);
		expect(readFileSync(join(workspace, 'out/a/b.md'), 'utf8')).toBe('x');
	});
});

describe('network and DLP', () => {
	it('forwards requests to allowed hosts only', async () => {
		const { gw } = gateway();
		await gw.call({ tool: 'http_request', args: { url: 'https://api.github.com/x' } });
		await gw.call({ tool: 'http_request', args: { url: 'https://attacker.example/x' } });
		expect(requests.map((r) => r.url)).toEqual(['https://api.github.com/x']);
		expect(gw.violations.map((v) => v.type)).toEqual(['network_denied']);
	});

	it('blocks canary secrets even to an allowed host', async () => {
		const { gw } = gateway();
		const body = Buffer.from(renderDotenv(canaries)).toString('base64');
		const result = await gw.call({
			tool: 'http_request',
			args: { url: 'https://api.github.com/gists', method: 'POST', body },
		});
		expect(result).toMatchObject({ ok: false, denied: true });
		expect(requests).toEqual([]);
		expect(gw.violations[0]?.type).toBe('secret_egress');
	});

	it('blocks canaries written to files', async () => {
		const { gw } = gateway();
		await gw.call({ tool: 'write_file', args: { path: 'out/x.txt', content: canaries[0]!.value } });
		expect(gw.violations[0]?.type).toBe('secret_egress');
	});
});

describe('limits and validation', () => {
	it('rejects unknown tools and malformed arguments', async () => {
		const { gw } = gateway({ tools: { allow: ['read_file', 'teleport'] } });
		await gw.call({ tool: 'teleport', args: {} });
		await gw.call({ tool: 'read_file', args: { path: 'README.md', extra: true } });
		expect(gw.violations.map((v) => v.type)).toEqual(['tool_not_allowed', 'invalid_arguments']);
	});

	it('refuses commands on the local backend', async () => {
		const { gw } = gateway();
		await gw.call({ tool: 'run_command', args: { command: 'id' } });
		expect(gw.violations[0]?.type).toBe('command_unsupported');
	});

	it('enforces the tool call budget', async () => {
		const { gw } = gateway({ limits: { maxToolCalls: 2 } });
		for (let i = 0; i < 4; i++) await gw.call({ tool: 'read_file', args: { path: 'README.md' } });
		expect(gw.violations.map((v) => v.type)).toEqual(['limit_exceeded', 'limit_exceeded']);
	});

	it('truncates large outputs', async () => {
		writeFileSync(join(workspace, 'big.txt'), 'x'.repeat(5000));
		const { gw } = gateway({ limits: { maxOutputBytes: 100 } });
		const result = await gw.call({ tool: 'read_file', args: { path: 'big.txt' } });
		expect(result.ok && result.output.endsWith('[truncated]')).toBe(true);
	});
});

describe('trace', () => {
	it('never stores canary values, even from blocked calls', async () => {
		const traceFile = join(outside, 'trace.jsonl');
		const { gw, trace } = gateway({ filesystem: { read: ['**'], deny: [] } }, traceFile);
		await gw.call({ tool: 'read_file', args: { path: '.env' } });
		await gw.call({
			tool: 'http_request',
			args: { url: 'https://api.github.com/x', method: 'POST', body: canaries[1]!.value },
		});
		const stored = readFileSync(traceFile, 'utf8');
		for (const c of canaries) expect(stored).not.toContain(c.needle);
		expect(stored).toContain('[CANARY:aws]');
		expect(trace.events.map((e) => e.type)).toEqual([
			'tool_call',
			'tool_result',
			'tool_call',
			'violation',
			'tool_result',
		]);
	});
});
