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
