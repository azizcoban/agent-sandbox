import { describe, expect, it } from 'vitest';
import { ClaudeAgent } from '../src/agents/claude.js';
import { mockModel } from '../src/agents/mock-model.js';
import { evaluate, formatEvalReport, mergeReports, rate } from '../src/eval.js';
import { scenarios } from '../src/scenarios/index.js';

const local = scenarios.filter((s) => !s.requiresCommands);
const injected = local.filter((s) => s.injection);
// The mock model only understands AGENT_DIRECTIVE lines.
const directive = injected.filter((s) => s.injection!.style === 'directive');

describe('rate', () => {
	it('computes a Wilson interval', () => {
		const none = rate(0, 3);
		expect(none.rate).toBe(0);
		expect(none.ci95[0]).toBe(0);
		expect(none.ci95[1]).toBeCloseTo(0.5615, 3);

		const all = rate(3, 3);
		expect(all.ci95[0]).toBeCloseTo(0.4385, 3);
		expect(all.ci95[1]).toBeCloseTo(1, 10);

		expect(rate(0, 0)).toEqual({ count: 0, of: 0, rate: 0, ci95: [0, 1] });
	});
});

describe('evaluate', () => {
	it('reports a 100% injection rate for an obedient model', async () => {
		const report = await evaluate({
			scenarios: local,
			trials: 2,
			agent: () => new ClaudeAgent({ model: 'mock', createMessage: mockModel({ followsInjections: true }) }),
		});

		expect(report.agent).toBe('claude:mock');
		expect(report.results).toHaveLength(local.length * 2);
		expect(report.injection).toMatchObject({ count: directive.length * 2, of: injected.length * 2 });

		const ipi = report.scenarios.find((s) => s.scenarioId === 'indirect-prompt-injection')!;
		expect(ipi.injection).toMatchObject({ count: 2, of: 2 });
		expect(ipi.statuses).toEqual({ clean: 0, contained: 2, breach: 0 });
		expect(ipi.violations).toEqual({ path_denied: 2, network_denied: 2 });

		const benign = report.scenarios.find((s) => s.scenarioId === 'benign-summary')!;
		expect(benign.injection).toBeUndefined();
		expect(benign.unsafe.count).toBe(0);
		expect(report.tokens.input).toBeGreaterThan(0);

		const text = formatEvalReport(report);
		expect(text).toContain('followed injection  2/2 (100%');
		expect(text).toContain(`Injection followed overall: ${directive.length * 2}/${injected.length * 2}`);
	});

	it('reports 0% for a resistant model', async () => {
		const report = await evaluate({
			scenarios: injected,
			trials: 3,
			agent: () => new ClaudeAgent({ createMessage: mockModel({ followsInjections: false }) }),
		});
		expect(report.injection).toMatchObject({ count: 0, of: injected.length * 3 });
		for (const s of report.scenarios) expect(s.statuses.clean).toBe(3);
	});

	it('records run errors and keeps going, but rethrows fatal ones', async () => {
		const failing = () =>
			new ClaudeAgent({
				createMessage: async () => {
					throw new Error('overloaded');
				},
			});
		const seen: string[] = [];
		const report = await evaluate({
			scenarios: injected,
			trials: 2,
			agent: failing,
			onTrial: (t) => seen.push(t.error ?? ''),
		});
		expect(seen).toEqual(Array(injected.length * 2).fill('overloaded'));
		expect(report.injection.of).toBe(0);
		expect(report.scenarios[0]!.errors).toBe(2);

		await expect(
			evaluate({ scenarios: injected, trials: 2, agent: failing, isFatal: () => true }),
		).rejects.toThrow('overloaded');
	});

	it('leaves refusals out of the injection rate', async () => {
		const report = await evaluate({
			scenarios: injected,
			trials: 2,
			agent: () => new ClaudeAgent({ createMessage: mockModel({ followsInjections: true, refuses: true }) }),
		});
		expect(report.injection).toMatchObject({ count: 0, of: 0 });
		expect(report.scenarios[0]).toMatchObject({ refusals: 2, injection: { of: 0 } });
		expect(formatEvalReport(report)).toContain('followed injection  n/a');
	});
});

describe('mergeReports', () => {
	const run = (ids: string[], followsInjections: boolean, model = 'mock') =>
		evaluate({
			scenarios: scenarios.filter((s) => ids.includes(s.id)),
			trials: 2,
			agent: () => new ClaudeAgent({ model, createMessage: mockModel({ followsInjections }) }),
		});

	it('combines scenarios and recomputes the overall injection rate', async () => {
		const first = await run(['benign-summary', 'indirect-prompt-injection'], true);
		const second = await run(['dlp-defense-in-depth'], false);
		second.startedAt = new Date(Date.parse(first.startedAt) + 1000).toISOString();
		const merged = mergeReports([second, first]);

		expect(merged.scenarios.map((s) => s.scenarioId)).toEqual([
			'benign-summary',
			'indirect-prompt-injection',
			'dlp-defense-in-depth',
		]);
		expect(merged.results).toHaveLength(6);
		expect(merged.injection).toMatchObject({ count: 2, of: 4 });
		expect(merged.tokens.input).toBe(first.tokens.input + second.tokens.input);
		expect(merged.startedAt).toBe(first.startedAt);
		// Older results carry no per-run date; they inherit their report's.
		const legacy = { ...first, results: first.results.map(({ startedAt, ...t }) => t) };
		expect(mergeReports([legacy, second]).results[0]!.startedAt).toBe(first.startedAt);
	});

	it('lets a later run replace a scenario', async () => {
		const first = await run(['indirect-prompt-injection'], true);
		const second = await run(['indirect-prompt-injection'], false);
		second.startedAt = new Date(Date.parse(first.startedAt) + 1000).toISOString();
		const merged = mergeReports([first, second]);
		expect(merged.results).toHaveLength(2);
		expect(merged.injection).toMatchObject({ count: 0, of: 2 });
	});

	it('refuses to merge different agents', async () => {
		const a = await run(['benign-summary'], false, 'a');
		const b = await run(['benign-summary'], false, 'b');
		expect(() => mergeReports([a, b])).toThrow('different agents');
	});
});
