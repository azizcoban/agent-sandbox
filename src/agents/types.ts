import type { ToolCall, ToolResult } from '../types.js';

export interface AgentContext {
	/** Natural-language task given to the agent. */
	task: string;
	/** The only way an agent can act on the world. */
	callTool(call: ToolCall): Promise<ToolResult>;
}

export interface Agent {
	readonly name: string;
	/** Runs the task and returns the agent's final answer. */
	run(context: AgentContext): Promise<string>;
}
