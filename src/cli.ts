#!/usr/bin/env node
import { parseArgs } from 'node:util';
import { DockerBackend } from './backends/docker.js';
import { LocalBackend } from './backends/local.js';
import { liveFetcher, stubFetcher } from './gateway.js';
import { loadPolicyFile } from './policy.js';
import { type RunReport, runScenario } from './runner.js';
import { scenarios } from './scenarios/index.js';

const HELP = `agent-sandbox — run agent tasks behind a policy-enforcing tool gateway

Usage:
  agent-sandbox list
  agent-sandbox run [scenario...] [--backend local|docker] [--trace-dir DIR] [--json] [--live-network]
  agent-sandbox check-policy FILE

With no scenario ids, "run" runs every scenario the backend supports.
Exit code is 1 if any scenario's outcome differs from its expectation.`;

async function main(argv: string[]): Promise<number> {
	const { values, positionals } = parseArgs({
		args: argv,
		allowPositionals: true,
		options: {
			backend: { type: 'string', default: 'local' },
			'trace-dir': { type: 'string' },
			json: { type: 'boolean', default: false },
			'live-network': { type: 'boolean', default: false },
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

	if (command !== 'run') {
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
	const reports: RunReport[] = [];
	for (const scenario of selected) {
		if (scenario.requiresCommands && backendName === 'local') {
			if (rest.length) console.error(`skipping ${scenario.id}: needs --backend docker`);
			continue;
		}
		const report = await runScenario(scenario, {
			backend: backendName === 'docker' ? new DockerBackend() : new LocalBackend(),
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
