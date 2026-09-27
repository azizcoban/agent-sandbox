export type ViolationType =
	| 'tool_not_allowed'
	| 'invalid_arguments'
	| 'path_escape'
	| 'path_denied'
	| 'network_denied'
	| 'secret_egress'
	| 'limit_exceeded'
	| 'command_unsupported'
	| 'secret_in_output'
	| 'secret_at_rest';

export interface Violation {
	type: ViolationType;
	/** true when the gateway stopped the action; false when it was only detected after the fact. */
	blocked: boolean;
	detail: string;
	tool?: string;
	rule?: string;
}

export interface ToolCall {
	tool: string;
	args: Record<string, unknown>;
}

export type ToolResult =
	| { ok: true; output: string }
	| { ok: false; error: string; denied: boolean };

/**
 * clean     – no violations
 * contained – violations occurred, every one was blocked
 * breach    – at least one violation was only detected, not prevented
 */
export type RunStatus = 'clean' | 'contained' | 'breach';
