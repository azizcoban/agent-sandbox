import { appendFileSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import type { CanaryDetector } from './canary.js';

export type TraceEventType =
	| 'run_start'
	| 'tool_call'
	| 'tool_result'
	| 'violation'
	| 'agent_output'
	| 'run_end';

export interface TraceEvent {
	runId: string;
	seq: number;
	ts: string;
	type: TraceEventType;
	data: Record<string, unknown>;
}

/**
 * Append-only structured trace. Every event is redacted before it is stored:
 * logs are an exfiltration surface too, so canary values never reach them.
 */
export class Trace {
	readonly events: TraceEvent[] = [];
	private seq = 0;

	constructor(
		readonly runId: string,
		private readonly detector: CanaryDetector,
		private readonly file?: string,
	) {
		if (file) mkdirSync(dirname(file), { recursive: true });
	}

	emit(type: TraceEventType, data: Record<string, unknown>): TraceEvent {
		const redacted = JSON.parse(this.detector.redact(JSON.stringify(data)));
		const event: TraceEvent = {
			runId: this.runId,
			seq: this.seq++,
			ts: new Date().toISOString(),
			type,
			data: redacted,
		};
		this.events.push(event);
		if (this.file) appendFileSync(this.file, JSON.stringify(event) + '\n');
		return event;
	}
}

/** One tool call (or post-run check) in a run, compact and already redacted. */
export interface TimelineStep {
	/** 1-based tool-call index, or 0 for a post-run scan. */
	n: number;
	/** Tool name, or "output scan" / "workspace scan" for post-run checks. */
	label: string;
	/** Short argument summary, e.g. "read .env" or "POST attacker.example/collect". */
	summary: string;
	outcome: 'ok' | 'blocked' | 'detected' | 'error';
	/** Reason, for a blocked, detected or errored step. */
	detail?: string;
}

/**
 * Builds a per-run timeline from trace events. Events are already redacted,
 * so the timeline carries no canary values. Each tool call becomes one step,
 * carrying the gateway's decision; post-run violations (output and workspace
 * scans) become their own steps.
 */
export function buildTimeline(events: TraceEvent[]): TimelineStep[] {
	const steps: TimelineStep[] = [];
	let current: TimelineStep | undefined;
	for (const { type, data } of events) {
		if (type === 'tool_call') {
			current = {
				n: Number(data.seq ?? steps.length + 1),
				label: String(data.tool ?? 'tool'),
				summary: summariseArgs(String(data.tool ?? ''), data.args),
				outcome: 'ok',
			};
			steps.push(current);
		} else if (type === 'tool_result' && current) {
			if (data.ok === false) {
				current.outcome = data.denied ? 'blocked' : 'error';
				if (!current.detail && typeof data.error === 'string') current.detail = data.error;
			}
			current = undefined;
		} else if (type === 'violation') {
			const detail = typeof data.detail === 'string' ? data.detail : undefined;
			if (data.blocked && current) {
				current.outcome = 'blocked';
				current.detail = detail;
			} else if (!data.blocked) {
				// Post-run detection: not tied to a tool call.
				const label = String(data.type) === 'secret_at_rest' ? 'workspace scan' : 'output scan';
				steps.push({ n: 0, label, summary: String(data.type ?? ''), outcome: 'detected', detail });
			}
		}
	}
	return steps;
}

function summariseArgs(tool: string, args: unknown): string {
	if (typeof args !== 'object' || args === null) return '';
	const a = args as Record<string, unknown>;
	if (tool === 'http_request') {
		const method = String(a.method ?? 'GET');
		try {
			const url = new URL(String(a.url));
			return `${method} ${url.host}${url.pathname === '/' ? '' : url.pathname}`;
		} catch {
			return `${method} ${String(a.url ?? '')}`;
		}
	}
	if (tool === 'run_command') return String(a.command ?? '');
	if ('path' in a) return String(a.path ?? '');
	return '';
}
