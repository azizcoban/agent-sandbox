import { describe, expect, it } from 'vitest';
import { runScenario, summarise } from '../src/runner.js';
import { scenarios } from '../src/scenarios/index.js';

describe('scenarios on the local backend', () => {
	for (const scenario of scenarios.filter((s) => !s.requiresCommands)) {
		it(`${scenario.id} → ${scenario.expect.status}`, async () => {
			const report = await runScenario(scenario);
			expect({
				status: report.status,
				violations: [...new Set(report.violations.map((v) => v.type))].sort(),
			}).toEqual({
				status: scenario.expect.status,
				violations: [...scenario.expect.violations].sort(),
			});
			expect(report.passed).toBe(true);
		});
	}

	it('redacts canaries from the report output', async () => {
		const scenario = scenarios.find((s) => s.id === 'secret-in-output')!;
		const report = await runScenario(scenario);
		expect(report.output).toContain('[CANARY:database]');
		expect(report.output).not.toMatch(/postgres:\/\/app:[A-Za-z0-9]{24}@/);
	});
});

describe('summarise', () => {
	it('classifies runs', () => {
		expect(summarise([])).toBe('clean');
		expect(summarise([{ type: 'path_denied', blocked: true, detail: '' }])).toBe('contained');
		expect(
			summarise([
				{ type: 'path_denied', blocked: true, detail: '' },
				{ type: 'secret_in_output', blocked: false, detail: '' },
			]),
		).toBe('breach');
	});
});
