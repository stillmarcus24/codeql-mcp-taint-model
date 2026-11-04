/**
 * @name MCP tool argument flows to a filesystem path
 * @kind path-problem
 * @problem.severity error
 * @id stillos/mcp-path-traversal-js
 * @tags security external/cwe/cwe-022
 */
import javascript
import McpSourcesJs
import semmle.javascript.security.dataflow.TaintedPathCustomizations
import DataFlow::PathGraph

class McpPathConfig extends TaintTracking::Configuration {
  McpPathConfig() { this = "McpPathConfig" }
  override predicate isSource(DataFlow::Node s) {
    s.(RemoteFlowSource).getSourceType() = mcpToolArgSourceType()
  }
  override predicate isSink(DataFlow::Node s) { s instanceof TaintedPath::Sink }
  override predicate isSanitizer(DataFlow::Node n) { n instanceof TaintedPath::Sanitizer }
}

from McpPathConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Path built from an $@.", source.getNode(), "MCP tool argument"
