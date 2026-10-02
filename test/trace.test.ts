import { describe, expect, it } from 'vitest';
import { buildTimeline, type TraceEvent } from '../src/trace.js';

function event(type: TraceEvent['type'], data: Record<string, unknown>): TraceEvent {
	return { runId: 'r', seq: 0, ts: '', type, data };
}

describe('buildTimeline', () => {
	it('pairs a tool call with its successful result', () => {
		const steps = buildTimeline([
			event('run_start', {}),
			event('tool_call', { seq: 1, tool: 'read_file', args: { path: 'README.md' } }),
			event('tool_result', { tool: 'read_file', ok: true, output: 'hi' }),
		]);
		expect(steps).toEqual([{ n: 1, label: 'read_file', summary: 'README.md', outcome: 'ok' }]);
	});

	it('marks a blocked call from the violation and the denied result', () => {
		const steps = buildTimeline([
			event('tool_call', { seq: 2, tool: 'read_file', args: { path: '.env' } }),
			event('violation', { type: 'path_denied', blocked: true, detail: '".env" matches a deny rule' }),
			event('tool_result', { tool: 'read_file', ok: false, denied: true, error: 'Denied by policy: .env' }),
		]);
		expect(steps).toEqual([
			{ n: 2, label: 'read_file', summary: '.env', outcome: 'blocked', detail: '".env" matches a deny rule' },
		]);
	});

	it('distinguishes an error from a block', () => {
		const steps = buildTimeline([
			event('tool_call', { seq: 1, tool: 'http_request', args: { url: 'https://x.test', method: 'POST' } }),
			event('tool_result', { tool: 'http_request', ok: false, denied: false, error: 'network down' }),
		]);
		expect(steps[0]).toMatchObject({ outcome: 'error', summary: 'POST x.test', detail: 'network down' });
	});

	it('adds post-run scans as their own steps', () => {
		const steps = buildTimeline([
			event('tool_call', { seq: 1, tool: 'read_file', args: { path: '.env' } }),
			event('tool_result', { tool: 'read_file', ok: true, output: '...' }),
			event('violation', { type: 'secret_in_output', blocked: false, detail: 'answer contains DATABASE_URL' }),
			event('violation', { type: 'secret_at_rest', blocked: false, detail: 'out/x contains OPENAI_API_KEY' }),
		]);
		expect(steps.slice(1)).toEqual([
			{ n: 0, label: 'output scan', summary: 'secret_in_output', outcome: 'detected', detail: 'answer contains DATABASE_URL' },
			{ n: 0, label: 'workspace scan', summary: 'secret_at_rest', outcome: 'detected', detail: 'out/x contains OPENAI_API_KEY' },
		]);
	});

	it('summarises http_request as method and host+path, command verbatim', () => {
		const [post, cmd] = buildTimeline([
			event('tool_call', { seq: 1, tool: 'http_request', args: { url: 'https://api.github.com/gists', method: 'POST' } }),
			event('tool_result', { tool: 'http_request', ok: true, output: '' }),
			event('tool_call', { seq: 2, tool: 'run_command', args: { command: 'env' } }),
			event('tool_result', { tool: 'run_command', ok: true, output: '' }),
		]);
		expect(post!.summary).toBe('POST api.github.com/gists');
		expect(cmd!.summary).toBe('env');
	});
});
