import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import type { Backend, BackendStartOptions, CommandResult } from './types.js';

const execFileAsync = promisify(execFile);

export interface DockerBackendOptions {
	image?: string;
	memory?: string;
	cpus?: string;
	pidsLimit?: number;
}

/**
 * Runs commands in a throwaway container with no network, no capabilities, a
 * read-only root filesystem and only the workspace mounted. The container is
 * the isolation boundary; the gateway remains the only way data leaves it.
 */
export class DockerBackend implements Backend {
	readonly name = 'docker';
	readonly supportsCommands = true;
	private containerId: string | undefined;

	constructor(private readonly options: DockerBackendOptions = {}) {}

	static async isAvailable(): Promise<boolean> {
		try {
			await execFileAsync('docker', ['info', '--format', '{{.ServerVersion}}'], {
				timeout: 10_000,
			});
			return true;
		} catch {
			return false;
		}
	}

	/** The `docker run` arguments, exposed so tests can assert the hardening flags. */
	runArgs({ workspace, env }: BackendStartOptions): string[] {
		const uid = typeof process.getuid === 'function' ? process.getuid() : 1000;
		const gid = typeof process.getgid === 'function' ? process.getgid() : 1000;
		const args = [
			'run',
			'--detach',
			'--rm',
			'--network', 'none',
			'--read-only',
			'--tmpfs', '/tmp:rw,noexec,nosuid,size=16m',
			'--cap-drop', 'ALL',
			'--security-opt', 'no-new-privileges',
			'--pids-limit', String(this.options.pidsLimit ?? 128),
			'--memory', this.options.memory ?? '256m',
			'--cpus', this.options.cpus ?? '1',
			'--user', `${uid === 0 ? 65534 : uid}:${gid === 0 ? 65534 : gid}`,
			'--volume', `${workspace}:/workspace:rw`,
			'--workdir', '/workspace',
		];
		// Names only: values reach docker through its own environment (see
		// start()), so secrets never appear in the process list or error messages.
		for (const key of Object.keys(env)) args.push('--env', key);
		args.push(this.options.image ?? 'alpine:3.20', 'sleep', 'infinity');
		return args;
	}

	async start(options: BackendStartOptions): Promise<void> {
		const { stdout } = await execFileAsync('docker', this.runArgs(options), {
			timeout: 120_000,
			env: { ...process.env, ...options.env },
		});
		this.containerId = stdout.trim();
	}

	async exec(command: string, timeoutMs: number): Promise<CommandResult> {
		if (!this.containerId) throw new Error('Container is not running');
		try {
			const { stdout, stderr } = await execFileAsync(
				'docker',
				['exec', this.containerId, 'sh', '-c', command],
				{ timeout: timeoutMs, maxBuffer: 4 * 1024 * 1024 },
			);
			return { exitCode: 0, stdout, stderr, timedOut: false };
		} catch (error) {
			const e = error as {
				code?: number | string;
				killed?: boolean;
				stdout?: string;
				stderr?: string;
			};
			return {
				exitCode: typeof e.code === 'number' ? e.code : -1,
				stdout: e.stdout ?? '',
				stderr: e.stderr ?? String(error),
				timedOut: Boolean(e.killed),
			};
		}
	}

	async stop(): Promise<void> {
		if (!this.containerId) return;
		const id = this.containerId;
		this.containerId = undefined;
		await execFileAsync('docker', ['rm', '--force', id], { timeout: 30_000 }).catch(
			() => undefined,
		);
	}
}
