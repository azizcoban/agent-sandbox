import { describe, expect, it } from 'vitest';
import { ClaudeAgent } from '../src/agents/claude.js';
import { mockModel } from '../src/agents/mock-model.js';
import { evaluate, formatEvalReport, rate } from '../src/eval.js';
import { scenarios } from '../src/scenarios/index.js';

const local = scenarios.filter((s) => !s.requiresCommands);
const injected = local.filter((s) => s.injection);

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
		expect(report.injection).toMatchObject({ count: injected.length * 2, of: injected.length * 2, rate: 1 });

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
		expect(text).toContain(`Injection followed overall: ${injected.length * 2}/${injected.length * 2}`);
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
});
