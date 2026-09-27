export interface CommandResult {
	exitCode: number;
	stdout: string;
	stderr: string;
	timedOut: boolean;
}

export interface BackendStartOptions {
	/** Absolute path of the workspace on the host. */
	workspace: string;
	/** Environment variables visible to commands (this is where env canaries go). */
	env: Record<string, string>;
}

/**
 * Where `run_command` executes. File and network tools never go through the
 * backend: the gateway performs them itself so policy is enforced in one place.
 */
export interface Backend {
	readonly name: string;
	readonly supportsCommands: boolean;
	start(options: BackendStartOptions): Promise<void>;
	exec(command: string, timeoutMs: number): Promise<CommandResult>;
	stop(): Promise<void>;
}
