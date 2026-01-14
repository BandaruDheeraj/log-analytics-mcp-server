"""
Log Analytics MCP Server

A Model Context Protocol server that enables querying Azure Log Analytics
workspaces using KQL. This bridges Azure SRE Agent with Log Analytics data
from resources in private VNets.
"""

import json
import logging
import os
import secrets
from datetime import timedelta

from azure.identity import DefaultAzureCredential
from azure.monitor.query import LogsQueryClient, LogsQueryStatus
from azure.core.exceptions import HttpResponseError
from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("log-analytics-mcp")

# API Key for authentication (optional - if not set, auth is disabled)
API_KEY = os.getenv("MCP_API_KEY")
API_KEY_HEADER = os.getenv("MCP_API_KEY_HEADER", "X-API-Key")

if API_KEY:
    logger.info(f"API key authentication enabled (header: {API_KEY_HEADER})")
else:
    logger.warning("No MCP_API_KEY set - authentication is disabled!")

# Initialize Azure credential
credential = DefaultAzureCredential()
logs_client = LogsQueryClient(credential)

# Get the Azure Container Apps host for allowed hosts
ACA_HOST = os.getenv("ACA_HOST", "log-analytics-mcp.happydune-ad37d82a.eastus2.azurecontainerapps.io")

# Disable DNS rebinding protection for cloud deployments where hostname varies
# This is safe when using API key authentication
transport_security = TransportSecuritySettings(
    enable_dns_rebinding_protection=False
)

# Create MCP server using FastMCP with stateless HTTP and JSON responses (recommended for production)
# stateless_http=True disables session management for scalable cloud deployments
mcp = FastMCP(
    "log-analytics-mcp-server",
    stateless_http=True,
    json_response=True,
    transport_security=transport_security
)


def get_workspace_id(workspace_id: str | None = None) -> str | None:
    """Get workspace ID from argument or environment."""
    return workspace_id or os.getenv("LOG_ANALYTICS_WORKSPACE_ID")


def parse_timespan(timespan: str | None) -> timedelta:
    """Parse ISO 8601 duration to timedelta."""
    if not timespan:
        return timedelta(hours=24)  # Default to last 24 hours
    
    # Handle common ISO 8601 durations
    timespan = timespan.upper()
    if timespan.startswith("PT"):
        # Hours and minutes: PT1H, PT30M, PT1H30M
        hours = 0
        minutes = 0
        remaining = timespan[2:]
        if "H" in remaining:
            h_idx = remaining.index("H")
            hours = int(remaining[:h_idx])
            remaining = remaining[h_idx + 1:]
        if "M" in remaining:
            m_idx = remaining.index("M")
            minutes = int(remaining[:m_idx])
        return timedelta(hours=hours, minutes=minutes)
    elif timespan.startswith("P"):
        # Days: P1D, P7D
        remaining = timespan[1:]
        if "D" in remaining:
            d_idx = remaining.index("D")
            days = int(remaining[:d_idx])
            return timedelta(days=days)
    
    # Default fallback
    return timedelta(hours=24)


def format_query_results(response) -> str:
    """Format Log Analytics query results as readable text."""
    if response.status == LogsQueryStatus.SUCCESS:
        tables = response.tables
        if not tables:
            return "Query returned no results."
        
        results = []
        for table in tables:
            # In newer SDK versions, columns are just strings
            columns = table.columns if isinstance(table.columns[0], str) else [col.name for col in table.columns]
            rows = []
            for row in table.rows:
                row_dict = dict(zip(columns, row))
                # Convert datetime objects to strings
                for k, v in row_dict.items():
                    if hasattr(v, 'isoformat'):
                        row_dict[k] = v.isoformat()
                rows.append(row_dict)
            
            results.append({
                "columns": columns,
                "row_count": len(rows),
                "rows": rows[:100]  # Limit to first 100 rows
            })
            
            if len(rows) > 100:
                results.append({"note": f"Showing first 100 of {len(rows)} rows"})
        
        return json.dumps(results, indent=2, default=str)
    
    elif response.status == LogsQueryStatus.PARTIAL:
        return f"Partial results returned. Error: {response.partial_error}"
    else:
        return f"Query failed with status: {response.status}"


@mcp.tool()
def query_logs(query: str, workspace_id: str = "", timespan: str = "P1D") -> str:
    """Execute a KQL query against an Azure Log Analytics workspace.

    Use this to query logs from VMs, containers, and other Azure resources.

    Common tables:
    - Syslog: Linux system logs
    - Perf: Performance counters (CPU, memory, disk)
    - Heartbeat: Agent heartbeat data
    - Event: Windows event logs
    - ContainerLog: Container stdout/stderr
    - AzureActivity: Azure resource activity

    Example queries:
    - "Syslog | where SeverityLevel == 'err' | take 10"
    - "Perf | where ObjectName == 'Processor' | summarize avg(CounterValue) by Computer"
    - "Heartbeat | summarize LastHeartbeat = max(TimeGenerated) by Computer"

    Args:
        query: The KQL query to execute
        workspace_id: Log Analytics workspace ID (GUID). Uses LOG_ANALYTICS_WORKSPACE_ID env var if empty.
        timespan: Time range in ISO 8601 duration format (e.g., PT1H, P1D, P7D). Default: P1D
    """
    ws_id = get_workspace_id(workspace_id if workspace_id else None)
    if not ws_id:
        return "Error: No workspace_id provided and LOG_ANALYTICS_WORKSPACE_ID environment variable not set."
    
    try:
        ts = parse_timespan(timespan)
        logger.info(f"Executing query on workspace {ws_id}: {query[:100]}...")
        
        response = logs_client.query_workspace(
            workspace_id=ws_id,
            query=query,
            timespan=ts
        )
        
        return format_query_results(response)
    
    except HttpResponseError as e:
        logger.error(f"Azure API error: {e}")
        return f"Azure API error: {e.message}\n\nMake sure you have 'Log Analytics Reader' role on the workspace."
    except Exception as e:
        logger.error(f"Error executing query: {e}")
        return f"Error: {str(e)}"


@mcp.tool()
def list_tables(workspace_id: str = "") -> str:
    """List available tables in a Log Analytics workspace.
    
    Use this to discover what data is available before querying.

    Args:
        workspace_id: Log Analytics workspace ID (GUID). Uses LOG_ANALYTICS_WORKSPACE_ID env var if empty.
    """
    ws_id = get_workspace_id(workspace_id if workspace_id else None)
    if not ws_id:
        return "Error: No workspace_id provided and LOG_ANALYTICS_WORKSPACE_ID environment variable not set."
    
    try:
        query = """
        search *
        | summarize Count = count() by $table
        | order by Count desc
        """
        
        response = logs_client.query_workspace(
            workspace_id=ws_id,
            query=query,
            timespan=timedelta(days=1)
        )
        
        result = format_query_results(response)
        return f"Available tables in workspace:\n{result}"
    
    except HttpResponseError as e:
        return f"Azure API error: {e.message}"
    except Exception as e:
        return f"Error: {str(e)}"


@mcp.tool()
def get_workspace_info(workspace_id: str = "") -> str:
    """Get metadata about a Log Analytics workspace including data volume by type.

    Args:
        workspace_id: Log Analytics workspace ID (GUID). Uses LOG_ANALYTICS_WORKSPACE_ID env var if empty.
    """
    ws_id = get_workspace_id(workspace_id if workspace_id else None)
    if not ws_id:
        return "Error: No workspace_id provided and LOG_ANALYTICS_WORKSPACE_ID environment variable not set."
    
    try:
        query = """
        Usage
        | where TimeGenerated > ago(1d)
        | summarize TotalMB = sum(Quantity) by DataType
        | order by TotalMB desc
        """
        
        response = logs_client.query_workspace(
            workspace_id=ws_id,
            query=query,
            timespan=timedelta(days=1)
        )
        
        result = format_query_results(response)
        return f"Workspace data usage (last 24h):\n{result}"
    
    except HttpResponseError as e:
        return f"Azure API error: {e.message}"
    except Exception as e:
        return f"Error: {str(e)}"


@mcp.tool()
def analyze_errors(workspace_id: str = "", timespan: str = "PT1H", computer_filter: str = "") -> str:
    """Analyze error patterns across VMs in a Log Analytics workspace.

    This is a convenience tool that runs pre-built queries to:
    - Find error-level syslog entries
    - Identify which computers have the most errors
    - Show recent error messages

    Use this as a starting point for incident investigation.

    Args:
        workspace_id: Log Analytics workspace ID (GUID). Uses LOG_ANALYTICS_WORKSPACE_ID env var if empty.
        timespan: Time range in ISO 8601 duration format. Default: PT1H
        computer_filter: Optional filter to specific computer name (partial match supported)
    """
    ws_id = get_workspace_id(workspace_id if workspace_id else None)
    if not ws_id:
        return "Error: No workspace_id provided and LOG_ANALYTICS_WORKSPACE_ID environment variable not set."
    
    try:
        ts = parse_timespan(timespan)
        filter_clause = f'| where Computer contains "{computer_filter}"' if computer_filter else ""
        
        # Error summary query
        summary_query = f"""
        Syslog
        | where SeverityLevel in ('err', 'crit', 'alert', 'emerg')
        {filter_clause}
        | summarize ErrorCount = count() by Computer
        | order by ErrorCount desc
        """
        
        summary_response = logs_client.query_workspace(
            workspace_id=ws_id,
            query=summary_query,
            timespan=ts
        )
        
        # Recent errors query
        recent_query = f"""
        Syslog
        | where SeverityLevel in ('err', 'crit', 'alert', 'emerg')
        {filter_clause}
        | project TimeGenerated, Computer, Facility, SeverityLevel, SyslogMessage
        | order by TimeGenerated desc
        | take 20
        """
        
        recent_response = logs_client.query_workspace(
            workspace_id=ws_id,
            query=recent_query,
            timespan=ts
        )
        
        summary_result = format_query_results(summary_response)
        recent_result = format_query_results(recent_response)
        
        return f"## Error Analysis\n\n### Errors by Computer:\n{summary_result}\n\n### Recent Errors:\n{recent_result}"
    
    except HttpResponseError as e:
        return f"Azure API error: {e.message}"
    except Exception as e:
        return f"Error: {str(e)}"


@mcp.tool()
def check_vm_health(workspace_id: str = "") -> str:
    """Check the health status of VMs reporting to Log Analytics.

    Shows:
    - Last heartbeat time for each VM
    - CPU and memory usage
    - Recent error count

    Use this to quickly assess which VMs might be having issues.

    Args:
        workspace_id: Log Analytics workspace ID (GUID). Uses LOG_ANALYTICS_WORKSPACE_ID env var if empty.
    """
    ws_id = get_workspace_id(workspace_id if workspace_id else None)
    if not ws_id:
        return "Error: No workspace_id provided and LOG_ANALYTICS_WORKSPACE_ID environment variable not set."
    
    try:
        query = """
        // Last heartbeat per computer
        let Heartbeats = Heartbeat
        | summarize LastHeartbeat = max(TimeGenerated) by Computer
        | extend MinutesSinceHeartbeat = datetime_diff('minute', now(), LastHeartbeat);
        
        // Recent CPU usage
        let CPUUsage = Perf
        | where ObjectName == 'Processor' and CounterName == '% Processor Time' and InstanceName == '_Total'
        | summarize AvgCPU = avg(CounterValue) by Computer;
        
        // Recent memory usage
        let MemoryUsage = Perf
        | where ObjectName == 'Memory' and CounterName == '% Used Memory'
        | summarize AvgMemory = avg(CounterValue) by Computer;
        
        // Recent error count
        let Errors = Syslog
        | where SeverityLevel in ('err', 'crit')
        | summarize ErrorCount = count() by Computer;
        
        // Join all data
        Heartbeats
        | join kind=leftouter CPUUsage on Computer
        | join kind=leftouter MemoryUsage on Computer
        | join kind=leftouter Errors on Computer
        | project 
            Computer,
            LastHeartbeat,
            MinutesSinceHeartbeat,
            AvgCPU = coalesce(AvgCPU, 0.0),
            AvgMemory = coalesce(AvgMemory, 0.0),
            ErrorCount = coalesce(ErrorCount, 0)
        | order by MinutesSinceHeartbeat desc
        """
        
        response = logs_client.query_workspace(
            workspace_id=ws_id,
            query=query,
            timespan=timedelta(hours=1)
        )
        
        result = format_query_results(response)
        return f"## VM Health Status\n\n{result}"
    
    except HttpResponseError as e:
        return f"Azure API error: {e.message}"
    except Exception as e:
        return f"Error: {str(e)}"


if __name__ == "__main__":
    import sys
    
    # Check for transport argument
    transport = "sse"
    port = int(os.getenv("PORT", "8000"))
    host = os.getenv("HOST", "0.0.0.0")  # Default to 0.0.0.0 for container deployments
    
    for i, arg in enumerate(sys.argv[1:], 1):
        if arg in ["--transport", "-t"]:
            if i < len(sys.argv) - 1:
                transport = sys.argv[i + 1]
        elif arg in ["--port", "-p"]:
            if i < len(sys.argv) - 1:
                port = int(sys.argv[i + 1])
        elif arg in ["--host"]:
            if i < len(sys.argv) - 1:
                host = sys.argv[i + 1]
        elif arg == "stdio":
            transport = "stdio"
        elif arg == "sse":
            transport = "sse"
    
    logger.info(f"Starting Log Analytics MCP Server with {transport} transport")
    
    if transport == "sse":
        logger.info(f"MCP endpoint will be at: http://{host}:{port}/mcp")
        logger.info(f"Health endpoint will be at: http://{host}:{port}/health")
        import contextlib
        import uvicorn
        from starlette.applications import Starlette
        from starlette.routing import Route, Mount
        from starlette.responses import JSONResponse
        from starlette.middleware import Middleware
        
        # Configure FastMCP for streamable HTTP
        mcp.settings.streamable_http_path = "/"
        
        logger.info("Using Streamable HTTP transport")
        
        # Health check endpoint
        async def health_check(request):
            return JSONResponse({"status": "healthy", "server": "log-analytics-mcp"})
        
        # API Key authentication middleware
        class APIKeyMiddleware(BaseHTTPMiddleware):
            async def dispatch(self, request, call_next):
                # Skip auth for health endpoint
                if request.url.path == "/health":
                    return await call_next(request)
                
                # If API key is configured, validate it
                if API_KEY:
                    provided_key = request.headers.get(API_KEY_HEADER)
                    if not provided_key:
                        logger.warning(f"Missing API key header: {API_KEY_HEADER}")
                        return JSONResponse(
                            {"error": "Missing API key", "header": API_KEY_HEADER},
                            status_code=401
                        )
                    if not secrets.compare_digest(provided_key, API_KEY):
                        logger.warning("Invalid API key provided")
                        return JSONResponse(
                            {"error": "Invalid API key"},
                            status_code=403
                        )
                
                return await call_next(request)
        
        # Create a combined lifespan to manage the session manager
        @contextlib.asynccontextmanager
        async def lifespan(app: Starlette):
            async with mcp.session_manager.run():
                yield
        
        # Create Starlette app with streamable HTTP mounted at /mcp
        app = Starlette(
            debug=True,
            routes=[
                Route("/health", health_check),
                Mount("/mcp", app=mcp.streamable_http_app()),
            ],
            lifespan=lifespan,
        )
        
        # Add authentication middleware
        app.add_middleware(APIKeyMiddleware)
        
        uvicorn.run(app, host=host, port=port)
    else:
        mcp.run(transport="stdio")
