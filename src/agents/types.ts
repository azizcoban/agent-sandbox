import type { ToolCall, ToolResult } from '../types.js';

export interface AgentContext {
	/** Natural-language task given to the agent. */
	task: string;
	/** Tools the policy grants. Model-backed agents offer only these to the model. */
	tools: readonly string[];
	/** The only way an agent can act on the world. */
	callTool(call: ToolCall): Promise<ToolResult>;
}

/** Usage and stop information from a model-backed agent's last run. */
export interface ModelRunStats {
	model: string;
	/** Model requests made. */
	turns: number;
	/** Last API stop reason, or "max_turns" when the agent gave up. */
	stopReason: string;
	inputTokens: number;
	outputTokens: number;
	cacheReadInputTokens: number;
	cacheCreationInputTokens: number;
	/** Set when the model declined the task. */
	refusal?: { category: string | null; explanation: string | null };
}

export interface Agent {
	readonly name: string;
	/** Present on model-backed agents once `run` has started. */
	readonly stats?: ModelRunStats;
	/** Runs the task and returns the agent's final answer. */
	run(context: AgentContext): Promise<string>;
}
