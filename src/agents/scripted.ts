import type { ToolCall, ToolResult } from '../types.js';
import type { Agent, AgentContext } from './types.js';

export interface StepRecord {
	call: ToolCall;
	result: ToolResult;
}

export type Step = ToolCall | ((history: StepRecord[]) => ToolCall | null);

export interface ScriptedAgentOptions {
	/** Final answer, optionally computed from what the agent saw. */
	output?: string | ((history: StepRecord[]) => string);
	/** Stop at the first denied call instead of carrying on. */
	stopOnDenied?: boolean;
}

/**
 * Deterministic agent that replays a fixed sequence of tool calls. Scenarios
 * use it to model a specific behaviour (benign, compromised, careless) so the
 * sandbox's controls are tested without depending on a model's mood.
 */
export class ScriptedAgent implements Agent {
	constructor(
		readonly name: string,
		private readonly steps: Step[],
		private readonly options: ScriptedAgentOptions = {},
	) {}

	async run(context: AgentContext): Promise<string> {
		const history: StepRecord[] = [];
		for (const step of this.steps) {
			const call = typeof step === 'function' ? step(history) : step;
			if (!call) continue;
			const result = await context.callTool(call);
			history.push({ call, result });
			if (this.options.stopOnDenied && !result.ok && result.denied) break;
		}
		const { output } = this.options;
		if (typeof output === 'function') return output(history);
		return output ?? `completed ${history.length} steps`;
	}
}
