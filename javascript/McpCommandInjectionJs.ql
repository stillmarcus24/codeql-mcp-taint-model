/**
 * @name MCP tool argument flows to a system command
 * @description An MCP tool-call argument — attacker-influencable via the LLM's context —
 *              reaches a command execution sink. CodeQL's default threat model does not
 *              treat MCP tool arguments as remote input, so the stock CommandInjection
 *              query reports nothing on these servers.
 * @kind path-problem
 * @problem.severity error
 * @precision high
 * @id stillos/mcp-command-injection-js
 * @tags security external/cwe/cwe-078
 */

import javascript
import McpSourcesJs
import semmle.javascript.security.dataflow.CommandInjectionCustomizations
import DataFlow::PathGraph

/**
 * Taint from MCP tool arguments to command-execution sinks.
 *
 * Sinks are reused verbatim from CodeQL's own CommandInjection customizations, so the
 * ONLY difference from the stock query is the source set. That is the point of the
 * measurement: same sinks, same engine, same sanitizers — swap in MCP sources and see
 * what the default threat model was hiding.
 */
class McpCmdConfig extends TaintTracking::Configuration {
  McpCmdConfig() { this = "McpCmdConfig" }

  override predicate isSource(DataFlow::Node source) {
    source.(RemoteFlowSource).getSourceType() = mcpToolArgSourceType()
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof CommandInjection::Sink
  }

  override predicate isSanitizer(DataFlow::Node node) {
    node instanceof CommandInjection::Sanitizer
  }
}

from McpCmdConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "Command built from an $@ reaches a system command execution.", source.getNode(),
  "MCP tool argument"
