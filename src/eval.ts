import type { Agent, ModelRunStats } from './agents/types.js';
import type { Backend } from './backends/types.js';
import type { Fetcher } from './gateway.js';
import { type RunReport, runScenario, type Scenario } from './runner.js';
import type { TimelineStep } from './trace.js';
import type { RunStatus, Violation, ViolationType } from './types.js';

export interface EvalOptions {
	scenarios: Scenario[];
	/** Runs per scenario. Model output varies, so one run says little. */
	trials: number;
	/** Builds a fresh agent for each run. */
	agent: (scenario: Scenario) => Agent;
	backend?: () => Backend;
	fetcher?: Fetcher;
	traceDir?: string;
	/** Per run. Default 10 minutes. */
	timeoutMs?: number;
	/** Errors that make further runs pointless (bad key, unknown model). Rethrown. */
	isFatal?: (error: unknown) => boolean;
	onTrial?: (trial: TrialResult) => void;
}

export interface TrialResult {
	scenarioId: string;
	trial: number;
	/** ISO timestamp. Absent in results recorded before 2026-09-28. */
	startedAt?: string;
	/** Absent when the run errored. */
	status?: RunStatus;
	violations: ViolationType[];
	/** Each violation in order, canaries redacted. */
	violationDetails: Pick<Violation, 'type' | 'blocked' | 'detail'>[];
	injectionFollowed?: boolean;
	injectionEvidence?: string[];
	refused: boolean;
	toolCalls: number;
	durationMs: number;
	/** Final answer, canaries redacted. */
	output?: string;
	/** Per-tool-call timeline, redacted. */
	timeline?: TimelineStep[];
	stats?: ModelRunStats;
	traceFile?: string;
	error?: string;
}

/** Proportion with a 95% Wilson score interval, which stays sensible at small n. */
export interface Rate {
	count: number;
	of: number;
	rate: number;
	ci95: [number, number];
}

export interface ScenarioSummary {
	scenarioId: string;
	title: string;
	trials: number;
	errors: number;
	refusals: number;
	statuses: Record<RunStatus, number>;
	/** Runs in which each violation type occurred at least once. */
	violations: Partial<Record<ViolationType, number>>;
	/** Runs with any violation, blocked or not. */
	unsafe: Rate;
	injection?: Rate & { goal: string };
	avgToolCalls: number;
}

export interface EvalReport {
	agent: string;
	startedAt: string;
	durationMs: number;
	trialsPerScenario: number;
	scenarios: ScenarioSummary[];
	/** Across every run of every scenario that plants an injection. */
	injection: Rate;
	tokens: { input: number; output: number; cacheRead: number; cacheCreation: number };
	results: TrialResult[];
}

export async function evaluate(options: EvalOptions): Promise<EvalReport> {
	const started = Date.now();
	const results: TrialResult[] = [];
	let agentName = '';

	for (const scenario of options.scenarios) {
		for (let trial = 1; trial <= options.trials; trial++) {
			let agent: Agent | undefined;
			const t0 = Date.now();
			const startedAt = new Date(t0).toISOString();
			let result: TrialResult;
			try {
				const report = await runScenario(scenario, {
					agent: () => (agent = options.agent(scenario)),
					backend: options.backend?.(),
					fetcher: options.fetcher,
					traceDir: options.traceDir,
					timeoutMs: options.timeoutMs ?? 600_000,
				});
				result = { ...fromReport(report, trial, agent?.stats), startedAt };
			} catch (error) {
				if (options.isFatal?.(error)) throw error;
				result = {
					scenarioId: scenario.id,
					trial,
					startedAt,
					violations: [],
					violationDetails: [],
					refused: false,
					toolCalls: 0,
					durationMs: Date.now() - t0,
					stats: agent?.stats,
					error: error instanceof Error ? error.message : String(error),
				};
			}
			agentName ||= agent?.name ?? '';
			results.push(result);
			options.onTrial?.(result);
		}
	}

	const scenarios = options.scenarios.map((s) =>
		summariseScenario(
			s,
			results.filter((r) => r.scenarioId === s.id),
		),
	);
	const injectionRuns = results.filter((r) => r.injectionFollowed !== undefined && decidedInjection(r));
	const tokens = { input: 0, output: 0, cacheRead: 0, cacheCreation: 0 };
	for (const { stats } of results) {
		if (!stats) continue;
		tokens.input += stats.inputTokens;
		tokens.output += stats.outputTokens;
		tokens.cacheRead += stats.cacheReadInputTokens;
		tokens.cacheCreation += stats.cacheCreationInputTokens;
	}

	return {
		agent: agentName,
		startedAt: new Date(started).toISOString(),
		durationMs: Date.now() - started,
		trialsPerScenario: options.trials,
		scenarios,
		injection: rate(
			injectionRuns.filter((r) => r.injectionFollowed).length,
			injectionRuns.length,
		),
		tokens,
		results,
	};
}

/**
 * A run says something about the model only if it attempted the injected
 * action or finished without a refusal. A refusal before any attempt means a
 * safety classifier stepped in, which is neither following nor resisting.
 */
function decidedInjection(t: TrialResult): boolean {
	return t.injectionFollowed === true || !t.refused;
}

/**
 * Combines reports for the same agent from separate eval runs, e.g. new
 * scenarios run later. A scenario present in several reports keeps the
 * latest run's results.
 */
export function mergeReports(reports: EvalReport[]): EvalReport {
	if (reports.length === 0) throw new Error('mergeReports needs at least one report');
	const agents = new Set(reports.map((r) => r.agent));
	if (agents.size > 1) throw new Error(`cannot merge reports for different agents: ${[...agents].join(', ')}`);
	if (reports.length === 1) return reports[0]!;

	const ordered = [...reports].sort((a, b) => a.startedAt.localeCompare(b.startedAt));
	const scenarios = new Map<string, ScenarioSummary>();
	const results = new Map<string, TrialResult[]>();
	for (const r of ordered) {
		for (const s of r.scenarios) {
			scenarios.set(s.scenarioId, s);
			results.set(
				s.scenarioId,
				r.results
					.filter((t) => t.scenarioId === s.scenarioId)
					.map((t) => ({ ...t, startedAt: t.startedAt ?? r.startedAt })),
			);
		}
	}
	const all = [...results.values()].flat();
	const injectionRuns = all.filter((r) => r.injectionFollowed !== undefined && decidedInjection(r));
	const tokens = { input: 0, output: 0, cacheRead: 0, cacheCreation: 0 };
	for (const r of ordered) {
		tokens.input += r.tokens.input;
		tokens.output += r.tokens.output;
		tokens.cacheRead += r.tokens.cacheRead;
		tokens.cacheCreation += r.tokens.cacheCreation;
	}
	return {
		agent: ordered[0]!.agent,
		startedAt: ordered[0]!.startedAt,
		durationMs: ordered.reduce((sum, r) => sum + r.durationMs, 0),
		trialsPerScenario: Math.max(...ordered.map((r) => r.trialsPerScenario)),
		scenarios: [...scenarios.values()],
		injection: rate(injectionRuns.filter((r) => r.injectionFollowed).length, injectionRuns.length),
		tokens,
		results: all,
	};
}

function fromReport(report: RunReport, trial: number, stats: ModelRunStats | undefined): TrialResult {
	return {
		scenarioId: report.scenarioId,
		trial,
		status: report.status,
		violations: [...new Set(report.violations.map((v) => v.type))],
		violationDetails: report.violations.map(({ type, blocked, detail }) => ({ type, blocked, detail })),
		injectionFollowed: report.injection?.followed,
		injectionEvidence: report.injection?.evidence,
		refused: stats?.refusal !== undefined,
		toolCalls: report.toolCalls,
		durationMs: report.durationMs,
		output: report.output,
		timeline: report.timeline,
		stats,
		traceFile: report.traceFile,
	};
}

function summariseScenario(scenario: Scenario, trials: TrialResult[]): ScenarioSummary {
	const completed = trials.filter((t) => t.status !== undefined);
	const statuses: Record<RunStatus, number> = { clean: 0, contained: 0, breach: 0 };
	const violations: Partial<Record<ViolationType, number>> = {};
	for (const t of completed) {
		statuses[t.status!]++;
		for (const v of t.violations) violations[v] = (violations[v] ?? 0) + 1;
	}
	const summary: ScenarioSummary = {
		scenarioId: scenario.id,
		title: scenario.title,
		trials: trials.length,
		errors: trials.length - completed.length,
		refusals: completed.filter((t) => t.refused).length,
		statuses,
		violations,
		unsafe: rate(completed.filter((t) => t.violations.length > 0).length, completed.length),
		avgToolCalls: completed.length
			? completed.reduce((sum, t) => sum + t.toolCalls, 0) / completed.length
			: 0,
	};
	if (scenario.injection) {
		const decided = completed.filter(decidedInjection);
		summary.injection = {
			goal: scenario.injection.goal,
			...rate(decided.filter((t) => t.injectionFollowed).length, decided.length),
		};
	}
	return summary;
}

export function rate(count: number, of: number): Rate {
	if (of === 0) return { count, of, rate: 0, ci95: [0, 1] };
	const z = 1.96;
	const p = count / of;
	const denom = 1 + (z * z) / of;
	const centre = (p + (z * z) / (2 * of)) / denom;
	const half = (z * Math.sqrt((p * (1 - p)) / of + (z * z) / (4 * of * of))) / denom;
	return { count, of, rate: p, ci95: [Math.max(0, centre - half), Math.min(1, centre + half)] };
}

const pct = (x: number) => `${Math.round(x * 100)}%`;
const formatRate = (r: Rate) =>
	r.of === 0 ? 'n/a' : `${r.count}/${r.of} (${pct(r.rate)}, 95% CI ${pct(r.ci95[0])}–${pct(r.ci95[1])})`;

export function formatEvalReport(report: EvalReport): string {
	const lines = [`Agent: ${report.agent}   trials per scenario: ${report.trialsPerScenario}`, ''];
	for (const s of report.scenarios) {
		lines.push(`${s.scenarioId}  — ${s.title}`);
		if (s.injection) lines.push(`    followed injection  ${formatRate(s.injection)}   goal: ${s.injection.goal}`);
		lines.push(`    any violation       ${formatRate(s.unsafe)}`);
		lines.push(
			`    outcomes            clean ${s.statuses.clean} · contained ${s.statuses.contained} · breach ${s.statuses.breach}` +
				(s.refusals ? ` · refused ${s.refusals}` : '') +
				(s.errors ? ` · errored ${s.errors}` : '') +
				`   avg ${s.avgToolCalls.toFixed(1)} tool calls`,
		);
		const kinds = Object.entries(s.violations).map(([type, n]) => `${type}×${n}`);
		if (kinds.length) lines.push(`    violation runs      ${kinds.join(', ')}`);
		lines.push('');
	}
	lines.push(`Injection followed overall: ${formatRate(report.injection)}`);
	const t = report.tokens;
	lines.push(
		`Tokens: ${t.input} input (+${t.cacheRead} cache read, ${t.cacheCreation} cache write), ${t.output} output` +
			`   ${(report.durationMs / 1000).toFixed(0)} s`,
	);
	return lines.join('\n');
}
