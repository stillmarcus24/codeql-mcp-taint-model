/**
 * MCP tool-call arguments as an untrusted (remote) taint source — JavaScript/TypeScript.
 *
 * Sibling of the Go model in ../incomplete-sanitizer/McpSources.qll. The Go model was
 * validated 2026-09-19 (4 servers: 3 stock findings -> 20 with the model, 17 net-new),
 * but it only covers `mark3labs/mcp-go`. Measured 2026-09-20: the real MCP corpus on
 * this box is 1,503 servers and **100% of them are JavaScript/TypeScript, zero Go**,
 * with 1,234 on the official `@modelcontextprotocol/sdk`. So the Go model covers ~none
 * of the actual ecosystem.
 *
 * The blind spot is real and was confirmed against a working control: grepping
 * codeql/javascript-all 2.10.1 for MCP terms returns 0 files, while `express` returns
 * 252, `fastify` 5 and `axios` 3, and `RemoteFlowSource` appears in 57. CodeQL models
 * plenty of frameworks; it does not model MCP. Consequence, measured on a real-world MCP server (undisclosed):
 * stock CommandInjection/TaintedPath/SqlInjection all report ZERO on a server that
 * runs `execSync(`command -v ${cmd}`, { shell: "/bin/bash" })` and exposes official-SDK
 * tools.
 *
 * Why these arguments are untrusted: an MCP server exposes tools that an LLM invokes,
 * with arguments derived from whatever is in that LLM's context — documents it read,
 * web pages it fetched, other tools' output, or a user. That is an attacker-reachable
 * channel, exactly like an HTTP request parameter. CodeQL's default threat model has no
 * entry for it, so every off-the-shelf injection query is silent.
 *
 * Coverage — each pattern is additive and deliberately name-scoped (precision over
 * recall), mirroring the Go model's design:
 *   1. high-level SDK:  server.tool(name, [schema,] handler) -> handler's args parameter
 *   2. high-level SDK:  server.registerTool(name, cfg, handler) -> same
 *   3. low-level SDK:   server.setRequestHandler(CallToolRequestSchema, handler)
 *                       -> request.params.arguments
 */

import javascript
private import semmle.javascript.security.dataflow.RemoteFlowSources

/** The canonical label for an MCP tool-argument source. Defined once; never inlined. */
string mcpToolArgSourceType() { result = "MCP tool-call argument" }

/**
 * The parameter of a callback passed to `server.tool(...)` / `server.registerTool(...)`.
 *
 * Both are the official `@modelcontextprotocol/sdk` high-level registration APIs. The
 * handler is the LAST argument; its FIRST parameter is the caller-supplied arguments
 * object (the SDK validates it against the declared zod schema, which constrains type
 * but never content — a string that must be a string can still be `; rm -rf /`).
 */
class McpHighLevelToolArg extends RemoteFlowSource {
  McpHighLevelToolArg() {
    exists(DataFlow::CallNode call, DataFlow::FunctionNode handler |
      call.getCalleeName() = ["tool", "registerTool"] and
      handler = call.getLastArgument().getALocalSource() and
      // the arguments object is the handler's first parameter
      this = handler.getParameter(0)
    )
  }

  override string getSourceType() { result = mcpToolArgSourceType() }
}

/**
 * `request.params.arguments` inside a `setRequestHandler(CallToolRequestSchema, ...)`
 * callback — the official SDK's low-level API.
 *
 * Scoped to a property read of `arguments` off a `params` property, so an unrelated
 * `.arguments` access is not treated as attacker input.
 */
class McpLowLevelRequestArgs extends RemoteFlowSource {
  McpLowLevelRequestArgs() {
    exists(DataFlow::CallNode reg, DataFlow::FunctionNode handler, DataFlow::ParameterNode req |
      reg.getCalleeName() = "setRequestHandler" and
      handler = reg.getLastArgument().getALocalSource() and
      req = handler.getParameter(0) and
      this = req.getAPropertyRead("params").getAPropertyRead("arguments")
    )
  }

  override string getSourceType() { result = mcpToolArgSourceType() }
}

/**
 * The whole `request` parameter of a CallTool handler, when the server destructures or
 * forwards it wholesale. Narrower guard than the above: only applies when the
 * registration explicitly names `CallToolRequestSchema`, so this cannot match a generic
 * request handler for some unrelated protocol.
 */
class McpCallToolRequest extends RemoteFlowSource {
  McpCallToolRequest() {
    exists(DataFlow::CallNode reg, DataFlow::FunctionNode handler |
      reg.getCalleeName() = "setRequestHandler" and
      reg.getArgument(0).asExpr().(Identifier).getName() = "CallToolRequestSchema" and
      handler = reg.getLastArgument().getALocalSource() and
      this = handler.getParameter(0)
    )
  }

  override string getSourceType() { result = mcpToolArgSourceType() }
}

// NOTE on the label: every query must filter sources via `mcpToolArgSourceType()`, never a
// string literal. An earlier version duplicated "MCP tool-call argument" as a literal in each
// query; one query drifted to "MCP tool argument", matched ZERO sources, and reported a clean
// zero on every server scanned — a silent false negative indistinguishable from a real result.
// The shared function is the single source of truth for that string.

