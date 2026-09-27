import type { Backend, CommandResult } from './types.js';

/**
 * In-process backend for policy tests. It deliberately cannot run commands:
 * executing agent-chosen shell commands on the host is exactly what this
 * project exists to avoid. Use the docker backend for that.
 */
export class LocalBackend implements Backend {
	readonly name = 'local';
	readonly supportsCommands = false;

	async start(): Promise<void> {}

	async exec(): Promise<CommandResult> {
		throw new Error('The local backend does not execute commands');
	}

	async stop(): Promise<void> {}
}
