/**
 * @name MCP tool argument flows to a SQL query
 * @kind path-problem
 * @problem.severity error
 * @id stillos/mcp-sql-injection-js
 * @tags security external/cwe/cwe-089
 *
 * MCP-argument -> SQL-sink taint, the exact class StillOS already landed as a live
 * Google OSS VRP P2 (googleapis/mcp-toolbox `escape`-bypass, 2026-07-12). Reuses the
 * proven MCP source model; sink = CodeQL's stock SqlInjection sink set (parameterized
 * query APIs are NOT sinks, so a correctly-bound query is a true negative, not a hit).
 */
import javascript
import McpSourcesJs
import semmle.javascript.security.dataflow.SqlInjectionCustomizations
import DataFlow::PathGraph

class McpSqlConfig extends TaintTracking::Configuration {
  McpSqlConfig() { this = "McpSqlConfig" }
  override predicate isSource(DataFlow::Node s) {
    s.(RemoteFlowSource).getSourceType() = mcpToolArgSourceType()
  }
  override predicate isSink(DataFlow::Node s) { s instanceof SqlInjection::Sink }
  override predicate isSanitizer(DataFlow::Node n) { n instanceof SqlInjection::Sanitizer }
}

from McpSqlConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "SQL query built from an $@.", source.getNode(), "MCP tool argument"
