# Log Analytics MCP Server

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![MCP](https://img.shields.io/badge/MCP-1.0-green.svg)](https://modelcontextprotocol.io/)

A [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server that enables AI agents to query Azure Log Analytics workspaces using KQL (Kusto Query Language). This bridges AI assistants like GitHub Copilot, Claude, and Azure SRE Agent with your observability data.

## 🎯 Use Cases

- **Incident Investigation**: Query logs from VMs, containers, and Azure resources during incidents
- **Private VNet Observability**: Access logs from resources with no public IPs via Log Analytics + Private Link
- **Cross-Resource Correlation**: Query multiple VMs/resources in a single natural language request
- **Performance Analysis**: Analyze CPU, memory, disk metrics across your infrastructure

## ✨ Features

| Tool | Description |
|------|-------------|
| `query_logs` | Execute any KQL query against Log Analytics |
| `list_tables` | Discover available tables in a workspace |
| `get_workspace_info` | Get data volume and usage statistics |
| `analyze_errors` | Pre-built error pattern analysis from Syslog |
| `check_vm_health` | VM health check (heartbeat, CPU, memory, errors) |

## 📋 Prerequisites

- **Python 3.10+**
- **Azure CLI** logged in (`az login`)
- **Log Analytics Reader** role on target workspace(s)

## 🚀 Quick Start

### 1. Clone and Install

```bash
git clone https://github.com/yourusername/log-analytics-mcp-server.git
cd log-analytics-mcp-server

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .\.venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt
```

### 2. Configure

```bash
# Set your Log Analytics workspace ID (the GUID from Azure Portal)
export LOG_ANALYTICS_WORKSPACE_ID="your-workspace-guid"

# Ensure you're logged into Azure
az login
```

### 3. Test

```bash
# Run the test script
python test_mcp.py
```

Expected output:
```
============================================================
LOG ANALYTICS MCP SERVER - VALIDATION TEST
============================================================

[1] MCP Server Info:
    Server name: log-analytics-mcp-server
    Tools registered: 5

[2] Testing list_tables()...
    ✅ SUCCESS - Retrieved table list
    Found 5 tables: ['Syslog', 'Perf', 'Heartbeat', ...]

[3] Testing query_logs()...
    ✅ SUCCESS - Query executed

============================================================
VALIDATION COMPLETE
============================================================
```

## 🔌 Integration

### VS Code / GitHub Copilot

Add to `.vscode/mcp.json`:

```json
{
  "servers": {
    "log-analytics": {
      "type": "stdio",
      "command": "python",
      "args": ["-c", "from server import mcp; mcp.run(transport='stdio')"],
      "cwd": "/path/to/log-analytics-mcp-server",
      "env": {
        "LOG_ANALYTICS_WORKSPACE_ID": "your-workspace-guid"
      }
    }
  }
}
```

### Claude Desktop

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "log-analytics": {
      "command": "python",
      "args": ["-c", "from server import mcp; mcp.run(transport='stdio')"],
      "cwd": "/path/to/log-analytics-mcp-server",
      "env": {
        "LOG_ANALYTICS_WORKSPACE_ID": "your-workspace-guid"
      }
    }
  }
}
```

### Azure SRE Agent

Add to your agent's MCP configuration:

```yaml
mcp_servers:
  - name: log-analytics
    command: python
    args: ["-c", "from server import mcp; mcp.run(transport='stdio')"]
    cwd: /path/to/log-analytics-mcp-server
    transport: stdio
    environment:
      LOG_ANALYTICS_WORKSPACE_ID: "your-workspace-guid"
```

## 📝 Example Usage

Once configured, you can ask your AI assistant:

> "Show me errors from my Log Analytics workspace in the last hour"

> "What VMs are sending heartbeats to my workspace?"

> "Query Syslog for any critical errors from web-vm"

> "Analyze the performance metrics for my database server"

### Direct Python Usage

```python
from server import query_logs, list_tables, check_vm_health

# List available tables
print(list_tables())

# Query for recent errors
result = query_logs(
    query="Syslog | where SeverityLevel == 'err' | take 10",
    timespan="PT1H"  # Last 1 hour
)
print(result)

# Check VM health
print(check_vm_health())
```

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    AI Assistant                              │
│         (GitHub Copilot, Claude, SRE Agent)                 │
│                                                             │
│  "Show me errors from app-vm in the last hour"              │
└─────────────────────┬───────────────────────────────────────┘
                      │ MCP Protocol (JSON-RPC over STDIO)
                      ▼
┌─────────────────────────────────────────────────────────────┐
│              Log Analytics MCP Server                        │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  Tools:                                              │   │
│  │  • query_logs        - Execute KQL queries           │   │
│  │  • list_tables       - Show available tables         │   │
│  │  • get_workspace_info - Workspace metadata           │   │
│  │  • analyze_errors    - Error pattern analysis        │   │
│  │  • check_vm_health   - VM health dashboard           │   │
│  └─────────────────────────────────────────────────────┘   │
│                           │                                 │
│                           │ azure-monitor-query SDK         │
│                           ▼                                 │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  Azure Monitor Query Client                          │   │
│  │  (DefaultAzureCredential)                            │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────┬───────────────────────────────────────┘
                      │ Azure Monitor Query API
                      ▼
┌─────────────────────────────────────────────────────────────┐
│              Log Analytics Workspace                         │
│                                                             │
│  Tables: Syslog, Perf, Heartbeat, ContainerLog, Event, etc. │
│                                                             │
│  Data from: VMs, Containers, Azure resources                │
│  (including private VNet resources via Private Link)        │
└─────────────────────────────────────────────────────────────┘
```

## 🔐 Authentication

This server uses `DefaultAzureCredential` which tries these methods in order:

1. **Environment variables** (`AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_CLIENT_SECRET`)
2. **Azure CLI** (`az login`)
3. **Azure Developer CLI** (`azd auth login`)
4. **Managed Identity** (when running in Azure)
5. **Visual Studio Code** credential
6. **Azure PowerShell** (`Connect-AzAccount`)

For local development, `az login` is the easiest option.

## 📊 Common KQL Queries

### Find recent errors
```kusto
Syslog
| where SeverityLevel in ('err', 'crit', 'alert', 'emerg')
| project TimeGenerated, Computer, Facility, SyslogMessage
| order by TimeGenerated desc
| take 20
```

### Check VM heartbeats
```kusto
Heartbeat
| summarize LastHeartbeat = max(TimeGenerated) by Computer
| extend MinutesAgo = datetime_diff('minute', now(), LastHeartbeat)
| order by MinutesAgo desc
```

### Performance analysis
```kusto
Perf
| where ObjectName == 'Processor' and CounterName == '% Processor Time'
| summarize AvgCPU = avg(CounterValue) by Computer, bin(TimeGenerated, 5m)
| order by TimeGenerated desc
```

### Container logs
```kusto
ContainerLog
| where LogEntrySource == 'stderr'
| project TimeGenerated, ContainerID, LogEntry
| order by TimeGenerated desc
| take 50
```

## 🔧 Configuration Options

| Environment Variable | Required | Description |
|---------------------|----------|-------------|
| `LOG_ANALYTICS_WORKSPACE_ID` | Yes | The GUID of your Log Analytics workspace |
| `AZURE_TENANT_ID` | No | Azure AD tenant ID (for service principal auth) |
| `AZURE_CLIENT_ID` | No | Service principal client ID |
| `AZURE_CLIENT_SECRET` | No | Service principal secret |

## 🧪 Development

### Run tests
```bash
python test_mcp.py
```

### Run with SSE transport (for web integrations)
```bash
python -c "from server import mcp; mcp.run(transport='sse')"
# Server starts on http://localhost:8000/sse
```

### Test with MCP Inspector
```bash
npx @modelcontextprotocol/inspector python -c "from server import mcp; mcp.run(transport='stdio')"
```

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📚 Related Resources

- [Model Context Protocol](https://modelcontextprotocol.io/)
- [Azure Monitor Query SDK](https://learn.microsoft.com/python/api/overview/azure/monitor-query-readme)
- [Kusto Query Language (KQL)](https://learn.microsoft.com/azure/data-explorer/kusto/query/)
- [Azure Log Analytics](https://learn.microsoft.com/azure/azure-monitor/logs/log-analytics-overview)
- [Azure Private Link for Azure Monitor](https://learn.microsoft.com/azure/azure-monitor/logs/private-link-security)
