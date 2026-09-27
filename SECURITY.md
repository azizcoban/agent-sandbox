# Security

agent-sandbox is a research and teaching tool. It demonstrates layered controls for AI agents: a policy-enforcing tool gateway, canary-based exfiltration detection and container isolation. It is not a certified isolation boundary. See *Limitations* in the README before relying on it for untrusted code.

## Design principles

- **Single enforcement point.** Every agent action is a tool call through `ToolGateway`; nothing else touches the host.
- **Deny by default.** Tools, paths and hosts must be explicitly allowed; the policy schema rejects unknown keys.
- **Defense in depth.** Policy, DLP and container isolation each assume the others can fail.
- **Detect what you can't prevent.** Output and workspace scans turn silent leaks into reported breaches.
- **Logs are an attack surface.** Canary values are redacted before trace events are stored, and secrets are passed to Docker by variable name, never on the command line.

## Reporting a vulnerability

If you find a way for an agent to bypass the gateway, such as escaping the workspace, reaching the network or exfiltrating a canary without detection, please open a GitHub security advisory rather than a public issue. Include the scenario or tool calls that reproduce it.
