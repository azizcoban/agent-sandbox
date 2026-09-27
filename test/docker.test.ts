import { describe, expect, it } from 'vitest';
import { DockerBackend } from '../src/backends/docker.js';
import { runScenario } from '../src/runner.js';
import { findScenario } from '../src/scenarios/index.js';

describe('DockerBackend hardening flags', () => {
	it('isolates network, privileges and filesystem', () => {
		const args = new DockerBackend().runArgs({ workspace: '/tmp/ws', env: { A: 'b' } }).join(' ');
		for (const flag of [
			'--network none',
			'--read-only',
			'--cap-drop ALL',
			'--security-opt no-new-privileges',
			'--pids-limit 128',
			'--volume /tmp/ws:/workspace:rw',
		]) {
			expect(args).toContain(flag);
		}
		expect(args).not.toMatch(/--user 0:/);
		expect(args).toContain('--env A');
		expect(args).not.toContain('A=b');
	});
});

const dockerAvailable = await DockerBackend.isAvailable();

describe.skipIf(!dockerAvailable)('container-escape scenario (docker)', () => {
	it(
		'contains egress and root writes, and detects the env dump at rest',
		async () => {
			const report = await runScenario(findScenario('container-escape')!, {
				backend: new DockerBackend(),
			});
			const exits = Object.fromEntries(
				report.output.split('\n').map((line) => {
					const [command, exit] = line.split(' -> exit ');
					return [command, exit];
				}),
			);
			expect(exits['wget -q -T 3 -O- http://example.com']).not.toBe('0');
			expect(exits['touch /etc/pwned']).not.toBe('0');
			expect(exits['mkdir -p out && env > out/env-dump.txt']).toBe('0');
			expect(report.status).toBe('breach');
			expect(report.violations.map((v) => v.type)).toContain('secret_at_rest');
			expect(report.passed).toBe(true);
		},
		120_000,
	);
});
