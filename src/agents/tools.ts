/**
 * Provider-neutral descriptions of the gateway's tools, for model-backed
 * agents. The gateway stays the source of truth for validation: these schemas
 * only tell the model what it may call, and a malformed call is still
 * rejected (and recorded) by the gateway.
 */
export interface ToolSpec {
	name: string;
	description: string;
	/** JSON Schema for the tool's arguments. */
	inputSchema: {
		type: 'object';
		properties: Record<string, unknown>;
		required?: string[];
		additionalProperties?: boolean;
	};
}

export const toolSpecs: readonly ToolSpec[] = [
	{
		name: 'read_file',
		description: 'Read a UTF-8 text file. Paths are relative to the repository root.',
		inputSchema: {
			type: 'object',
			properties: { path: { type: 'string', description: 'File path relative to the repository root.' } },
			required: ['path'],
			additionalProperties: false,
		},
	},
	{
		name: 'write_file',
		description: 'Create or overwrite a text file. Parent directories are created as needed.',
		inputSchema: {
			type: 'object',
			properties: {
				path: { type: 'string', description: 'File path relative to the repository root.' },
				content: { type: 'string', description: 'Full file content.' },
			},
			required: ['path', 'content'],
			additionalProperties: false,
		},
	},
	{
		name: 'list_dir',
		description: 'List the entries of a directory. Directory names end with "/".',
		inputSchema: {
			type: 'object',
			properties: { path: { type: 'string', description: 'Directory path; "." is the repository root.' } },
			additionalProperties: false,
		},
	},
	{
		name: 'run_command',
		description: 'Run a shell command in the repository root. Returns JSON with exitCode, stdout and stderr.',
		inputSchema: {
			type: 'object',
			properties: { command: { type: 'string' } },
			required: ['command'],
			additionalProperties: false,
		},
	},
	{
		name: 'http_request',
		description: 'Make an HTTP request. Returns JSON with the response status and body.',
		inputSchema: {
			type: 'object',
			properties: {
				url: { type: 'string' },
				method: { type: 'string', enum: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'] },
				headers: { type: 'object', additionalProperties: { type: 'string' } },
				body: { type: 'string' },
			},
			required: ['url'],
			additionalProperties: false,
		},
	},
];

/** Specs for the granted tools, in a stable order so the request prefix caches. */
export function specsFor(granted: readonly string[]): ToolSpec[] {
	return toolSpecs.filter((spec) => granted.includes(spec.name));
}
