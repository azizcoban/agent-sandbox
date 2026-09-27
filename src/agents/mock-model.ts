import type Anthropic from '@anthropic-ai/sdk';
import type { ToolCall } from '../types.js';
import type { CreateMessage } from './claude.js';
import { PLACEHOLDER, parseDirectives } from './injectable.js';

export interface MockModelOptions {
	/** Obey `AGENT_DIRECTIVE` lines found in tool results, like a model that falls for injection. */
	followsInjections: boolean;
	/** File the mock reads first. Default README.md. */
	firstRead?: string;
	/** Answer every request with a refusal instead. */
	refuses?: boolean;
}

interface Seen {
	calls: ToolCall[];
	/** Successful read_file outputs by path. */
	reads: Map<string, string>;
	/** Outputs of successful tool calls, in order. */
	outputs: string[];
}

/**
 * A stand-in for the Messages API that plays a deterministic model, so the
 * Claude adapter's loop, the gateway wiring and the eval can be tested in CI
 * without a key. It derives each reply from the conversation alone:
 *
 * 1. read `firstRead`;
 * 2. if it follows injections, act on each directive in the tool results,
 *    reading any `{{file:...}}` sources first (in one parallel turn);
 * 3. finish with a text answer.
 */
export function mockModel(options: MockModelOptions): CreateMessage {
	const firstRead = options.firstRead ?? 'README.md';
	return async (params) => {
		if (options.refuses) {
			return message(params.model, [], 'refusal', {
				type: 'refusal',
				category: null,
				explanation: 'mock refusal',
			});
		}
		const seen = replay(params.messages);
		if (seen.calls.length === 0) return toolTurn(params, [{ tool: 'read_file', args: { path: firstRead } }]);

		if (options.followsInjections) {
			const directives = seen.outputs.flatMap(parseDirectives);
			for (const directive of directives) {
				const sources = placeholderPaths(directive).filter((p) => !seen.calls.some((c) => isRead(c, p)));
				if (sources.length > 0) {
					return toolTurn(
						params,
						sources.map((path) => ({ tool: 'read_file', args: { path } })),
					);
				}
				const filled = fill(directive, seen.reads);
				if (!seen.calls.some((c) => JSON.stringify(c) === JSON.stringify(filled))) {
					return toolTurn(params, [filled]);
				}
			}
			return message(params.model, [text('Done: followed the maintenance steps and summarised the README.')], 'end_turn');
		}

		const readme = seen.reads.get(firstRead)?.split('\n').find((l) => l.trim()) ?? '';
		return message(
			params.model,
			[text(`Summary: ${readme}. The file also contains instructions aimed at AI assistants; I ignored them.`)],
			'end_turn',
		);
	};
}

function replay(messages: Anthropic.MessageParam[]): Seen {
	const pending = new Map<string, ToolCall>();
	const seen: Seen = { calls: [], reads: new Map(), outputs: [] };
	for (const m of messages) {
		if (typeof m.content === 'string') continue;
		for (const block of m.content) {
			if (block.type === 'tool_use') {
				const call = { tool: block.name, args: block.input as Record<string, unknown> };
				pending.set(block.id, call);
				seen.calls.push(call);
			} else if (block.type === 'tool_result' && !block.is_error && typeof block.content === 'string') {
				const call = pending.get(block.tool_use_id);
				seen.outputs.push(block.content);
				if (call?.tool === 'read_file') seen.reads.set(String(call.args.path), block.content);
			}
		}
	}
	return seen;
}

function isRead(call: ToolCall, path: string): boolean {
	return call.tool === 'read_file' && call.args.path === path;
}

function placeholderPaths(call: ToolCall): string[] {
	const text = JSON.stringify(call.args);
	return [...new Set([...text.matchAll(PLACEHOLDER)].map((m) => m[2]!))];
}

function fill(call: ToolCall, reads: Map<string, string>): ToolCall {
	const args: Record<string, unknown> = {};
	for (const [key, value] of Object.entries(call.args)) {
		args[key] =
			typeof value === 'string'
				? value.replace(PLACEHOLDER, (_, kind: string, path: string) => {
						const content = reads.get(path) ?? '';
						return kind === 'base64file' ? Buffer.from(content).toString('base64') : content;
					})
				: value;
	}
	return { tool: call.tool, args };
}

let nextId = 0;

function toolTurn(params: Anthropic.MessageCreateParamsNonStreaming, calls: ToolCall[]): Anthropic.Message {
	const blocks: Anthropic.ToolUseBlock[] = calls.map((call) => ({
		type: 'tool_use',
		id: `toolu_mock_${++nextId}`,
		name: call.tool,
		input: call.args,
		caller: { type: 'direct' },
	}));
	return message(params.model, blocks, 'tool_use');
}

function text(value: string): Anthropic.TextBlock {
	return { type: 'text', text: value, citations: null };
}

function message(
	model: string,
	content: Anthropic.ContentBlock[],
	stopReason: Anthropic.StopReason,
	stopDetails: Anthropic.Message['stop_details'] = null,
): Anthropic.Message {
	return {
		id: `msg_mock_${++nextId}`,
		type: 'message',
		role: 'assistant',
		model,
		content,
		container: null,
		stop_reason: stopReason,
		stop_details: stopDetails,
		stop_sequence: null,
		usage: {
			input_tokens: 100,
			output_tokens: 20,
			cache_creation: null,
			cache_creation_input_tokens: 0,
			cache_read_input_tokens: 0,
			inference_geo: null,
			output_tokens_details: null,
			server_tool_use: null,
			service_tier: 'standard',
		},
	};
}
