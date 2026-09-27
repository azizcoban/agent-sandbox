#!/usr/bin/env node
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { parseArgs } from 'node:util';
import Anthropic from '@anthropic-ai/sdk';
import { ClaudeAgent, type Effort } from './agents/claude.js';
import { mockModel } from './agents/mock-model.js';
import { DockerBackend } from './backends/docker.js';
import { LocalBackend } from './backends/local.js';
import { liveFetcher, stubFetcher } from './gateway.js';
import { evaluate, formatEvalReport } from './eval.js';
import { loadPolicyFile } from './policy.js';
import { type RunReport, runScenario, type Scenario } from './runner.js';
import { scenarios } from './scenarios/index.js';

const HELP = `agent-sandbox — run agent tasks behind a policy-enforcing tool gateway

Usage:
  agent-sandbox list
  agent-sandbox run [scenario...] [--backend local|docker] [--trace-dir DIR] [--json] [--live-network]
  agent-sandbox eval [scenario...] [--model ID] [--trials N] [--effort LEVEL] [--out FILE]
                     [--workspace ID] [--backend local|docker] [--trace-dir DIR] [--json] [--mock obedient|resistant]
  agent-sandbox check-policy FILE

With no scenario ids, "run" and "eval" use every scenario the backend supports.
"run" uses each scenario's scripted agent; exit code is 1 if any outcome
differs from its expectation.
"eval" swaps in a Claude model (default claude-opus-5, key from ANTHROPIC_API_KEY
or ./.env; --workspace or ANTHROPIC_WORKSPACE_ID for keys not scoped to a
workspace), runs each scenario --trials times (default 3) and reports how often
the model followed injected instructions. --mock replaces the API with a
deterministic local model, for CI.`;

async function main(argv: string[]): Promise<number> {
	const { values, positionals } = parseArgs({
		args: argv,
		allowPositionals: true,
		options: {
			backend: { type: 'string', default: 'local' },
			'trace-dir': { type: 'string' },
			json: { type: 'boolean', default: false },
			'live-network': { type: 'boolean', default: false },
			model: { type: 'string', default: 'claude-opus-5' },
			trials: { type: 'string', default: '3' },
			effort: { type: 'string' },
			out: { type: 'string' },
			mock: { type: 'string' },
			workspace: { type: 'string' },
			help: { type: 'boolean', short: 'h', default: false },
		},
	});
	const [command, ...rest] = positionals;

	if (values.help || !command) {
		console.log(HELP);
		return 0;
	}

	if (command === 'list') {
		for (const s of scenarios) {
			const tag = s.requiresCommands ? ' [docker]' : '';
			console.log(`${s.id.padEnd(28)} ${s.title}${tag}`);
		}
		return 0;
	}

	if (command === 'check-policy') {
		if (!rest[0]) throw new Error('check-policy needs a file');
		console.log(JSON.stringify(loadPolicyFile(rest[0]), null, 2));
		return 0;
	}

	if (command !== 'run' && command !== 'eval') {
		console.error(`Unknown command "${command}"\n\n${HELP}`);
		return 2;
	}

	const backendName = values.backend;
	if (backendName !== 'local' && backendName !== 'docker') {
		throw new Error(`Unknown backend "${backendName}"`);
	}
	if (backendName === 'docker' && !(await DockerBackend.isAvailable())) {
		throw new Error('Docker is not available. Start the Docker daemon or use --backend local.');
	}

	const selected = rest.length ? rest.map(findOrThrow) : scenarios;
	const newBackend = () => (backendName === 'docker' ? new DockerBackend() : new LocalBackend());
	const runnable = (scenario: Scenario) => {
		if (!scenario.requiresCommands || backendName === 'docker') return true;
		if (rest.length) console.error(`skipping ${scenario.id}: needs --backend docker`);
		return false;
	};

	if (command === 'eval') {
		return runEval(selected.filter(runnable), values, newBackend);
	}

	const reports: RunReport[] = [];
	for (const scenario of selected.filter(runnable)) {
		const report = await runScenario(scenario, {
			backend: newBackend(),
			fetcher: values['live-network'] ? liveFetcher : stubFetcher,
			traceDir: values['trace-dir'],
		});
		reports.push(report);
		if (!values.json) printReport(report);
	}

	if (values.json) console.log(JSON.stringify(reports, null, 2));
	const failed = reports.filter((r) => !r.passed).length;
	if (!values.json) {
		console.log(`\n${reports.length - failed}/${reports.length} scenarios behaved as expected`);
	}
	return failed > 0 ? 1 : 0;
}

const EFFORTS: readonly Effort[] = ['low', 'medium', 'high', 'xhigh', 'max'];

async function runEval(
	selected: Scenario[],
	values: {
		model: string;
		trials: string;
		effort?: string;
		out?: string;
		mock?: string;
		workspace?: string;
		json: boolean;
		'trace-dir'?: string;
		'live-network': boolean;
	},
	newBackend: () => LocalBackend | DockerBackend,
): Promise<number> {
	const trials = Number(values.trials);
	if (!Number.isInteger(trials) || trials < 1) throw new Error('--trials must be a positive integer');
	const effort = values.effort as Effort | undefined;
	if (effort && !EFFORTS.includes(effort)) throw new Error(`--effort must be one of ${EFFORTS.join(', ')}`);
	if (values.mock && values.mock !== 'obedient' && values.mock !== 'resistant') {
		throw new Error('--mock must be "obedient" or "resistant"');
	}
	const createMessage = values.mock
		? mockModel({ followsInjections: values.mock === 'obedient' })
		: undefined;
	if (!createMessage && !process.env.ANTHROPIC_API_KEY && existsSync('.env')) {
		// Only the host process sees this key; agents' workspaces get canaries instead.
		process.loadEnvFile('.env');
	}

	const report = await evaluate({
		scenarios: selected,
		trials,
		agent: () =>
			new ClaudeAgent({ model: values.model, effort, workspaceId: values.workspace, createMessage }),
		backend: newBackend,
		fetcher: values['live-network'] ? liveFetcher : stubFetcher,
		traceDir: values['trace-dir'],
		isFatal: (error) =>
			error instanceof Anthropic.AuthenticationError ||
			error instanceof Anthropic.PermissionDeniedError ||
			error instanceof Anthropic.NotFoundError ||
			error instanceof Anthropic.BadRequestError,
		onTrial: (t) => {
			if (values.json) return;
			const outcome = t.error
				? `error: ${t.error}`
				: `${t.status}${t.injectionFollowed ? ', followed injection' : ''}${t.refused ? ', refused' : ''}`;
			console.error(`  ${t.scenarioId} #${t.trial}: ${outcome} (${t.toolCalls} tool calls)`);
		},
	});

	if (values.out) {
		mkdirSync(dirname(values.out), { recursive: true });
		writeFileSync(values.out, JSON.stringify(report, null, 2));
	}
	console.log(values.json ? JSON.stringify(report, null, 2) : `\n${formatEvalReport(report)}`);
	// A measurement, not a pass/fail gate: only fail when nothing ran.
	return report.results.every((r) => r.error) ? 1 : 0;
}

function findOrThrow(id: string) {
	const scenario = scenarios.find((s) => s.id === id);
	if (!scenario) throw new Error(`Unknown scenario "${id}". Try: agent-sandbox list`);
	return scenario;
}

const STATUS_ICON = { clean: '●', contained: '■', breach: '▲' } as const;

function printReport(r: RunReport): void {
	const mark = r.passed ? 'PASS' : 'FAIL';
	console.log(
		`\n${mark}  ${r.scenarioId}  ${STATUS_ICON[r.status]} ${r.status}` +
			`  (expected ${r.expected.status}; ${r.toolCalls} tool calls, ${r.durationMs} ms)`,
	);
	for (const v of r.violations) {
		console.log(`      ${v.blocked ? 'blocked ' : 'DETECTED'}  ${v.type.padEnd(20)} ${v.detail}`);
	}
	if (r.traceFile) console.log(`      trace: ${r.traceFile}`);
}

main(process.argv.slice(2)).then(
	(code) => process.exit(code),
	(error: unknown) => {
		console.error(error instanceof Error ? error.message : error);
		process.exit(2);
	},
);
