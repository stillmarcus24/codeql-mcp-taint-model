# CodeQL taint model for MCP tool-call arguments (JavaScript/TypeScript)

CodeQL's default threat model does not treat **Model Context Protocol (MCP) tool-call arguments** as untrusted input. But those arguments come from an LLM's context (documents it read, pages it fetched, other tools' output), which makes them an attacker-reachable channel, just like an HTTP parameter. As a result, the stock `CommandInjection`, `TaintedPath` and `SqlInjection` queries report **nothing** on MCP servers that pass tool arguments straight into a shell.

This pack adds MCP tool arguments as a remote flow source for the official `@modelcontextprotocol/sdk` registration APIs (`server.tool`, `server.registerTool`, low-level `setRequestHandler(CallToolRequestSchema, ...)`), plus three path-problem queries:

- `McpCommandInjectionJs.ql` (CWE-78)
- `McpPathTraversalJs.ql` (CWE-22)
- `McpSqlInjectionJs.ql` (CWE-89)

**Results.** On the first server tested, stock CodeQL found 7 taint flows; with this model it surfaced 27 more that the stock queries structurally cannot see. Candidates were confirmed by hand before reporting. This work led to three MITRE-assigned CVEs, all CWE-78 command injection to RCE, CVSS 7.5, published 2026-10-23:

- [CVE-2026-106763](https://osv.dev/vulnerability/GHSA-2vq3-mpmf-9xgr) (`@justice8096/sagemath-mcp-server`)
- CVE-2026-106764 (`@rog0x/mcp-git-tools`)
- CVE-2026-106765 (`@rog0x/mcp-docker-tools`)

Machine-readable advisories (OSV format): https://stillosdigitalholdings.com/advisories/osv

**Usage.** `codeql database create db --language=javascript --source-root <server>` then `codeql database analyze db javascript/ --format=sarif-latest --output=out.sarif`. Pinned to `codeql/javascript-all` 2.10.1.

Precision over recall: source patterns are name-scoped to the official SDK, so expect false negatives on custom registration wrappers.

Author: Marcus Still, Still OS Digital Holdings LLC. MIT License.
