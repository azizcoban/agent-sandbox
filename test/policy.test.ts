import { describe, expect, it } from 'vitest';
import { PolicyEngine, parsePolicy } from '../src/policy.js';

const engine = (overrides: Record<string, unknown> = {}) =>
	new PolicyEngine(
		parsePolicy({
			version: 1,
			tools: { allow: ['read_file', 'http_request'] },
			filesystem: { read: ['.', '**'], write: ['out/**'], deny: ['.env', '**/*.pem'] },
			network: { allowHosts: ['api.github.com', '*.example.org'] },
			...overrides,
		}),
	);

describe('parsePolicy', () => {
	it('fills defaults', () => {
		const policy = parsePolicy({ version: 1 });
		expect(policy.tools.allow).toEqual([]);
		expect(policy.network.allowHosts).toEqual([]);
		expect(policy.limits.maxToolCalls).toBe(50);
		expect(policy.dlp.scanTools).toContain('http_request');
	});

	it('rejects unknown keys so typos cannot silently widen access', () => {
		expect(() => parsePolicy({ version: 1, filesytem: { read: ['**'] } })).toThrow();
		expect(() => parsePolicy({ version: 1, network: { allowHost: ['*'] } })).toThrow();
	});
});

describe('tools', () => {
	it('allows only listed tools', () => {
		expect(engine().checkTool('read_file').allow).toBe(true);
		expect(engine().checkTool('run_command').allow).toBe(false);
	});
});

describe('filesystem', () => {
	it('lets deny win over read', () => {
		expect(engine().checkPath('.env', 'read').allow).toBe(false);
		expect(engine().checkPath('certs/server.pem', 'read').allow).toBe(false);
		expect(engine().checkPath('src/app.ts', 'read').allow).toBe(true);
	});

	it('limits writes to the write globs', () => {
		expect(engine().checkPath('out/report.md', 'write').allow).toBe(true);
		expect(engine().checkPath('src/app.ts', 'write').allow).toBe(false);
	});

	it('treats the workspace root as "."', () => {
		expect(engine().checkPath('', 'read').allow).toBe(true);
		const noRoot = engine({ filesystem: { read: ['**'] } });
		expect(noRoot.checkPath('', 'read').allow).toBe(false);
	});

	it('denies everything when no globs are given', () => {
		const none = engine({ filesystem: {} });
		expect(none.checkPath('README.md', 'read').allow).toBe(false);
	});
});

describe('network', () => {
	it('matches exact hosts and subdomain wildcards', () => {
		const e = engine();
		expect(e.checkUrl('https://api.github.com/repos').allow).toBe(true);
		expect(e.checkUrl('https://docs.example.org/').allow).toBe(true);
		expect(e.checkUrl('https://example.org/').allow).toBe(false);
		expect(e.checkUrl('https://api.github.com.attacker.net/').allow).toBe(false);
		expect(e.checkUrl('https://evil-api.github.com/').allow).toBe(false);
	});

	it('rejects non-http schemes, credentials and garbage', () => {
		const e = engine();
		expect(e.checkUrl('file:///etc/passwd').allow).toBe(false);
		expect(e.checkUrl('https://user:pass@api.github.com/').allow).toBe(false);
		expect(e.checkUrl('not a url').allow).toBe(false);
	});

	it('denies all egress by default', () => {
		const e = engine({ network: {} });
		expect(e.checkUrl('https://api.github.com/').allow).toBe(false);
	});
});
