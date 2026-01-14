# Log Analytics MCP Server

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![MCP](https://img.shields.io/badge/MCP-1.0-green.svg)](https://modelcontextprotocol.io/)

A [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server that enables AI agents to query Azure Log Analytics workspaces using KQL (Kusto Query Language). This bridges AI assistants like GitHub Copilot, Claude, and Azure SRE Agent with your observability data.

**Supports both local (stdio) and remote (Streamable HTTP) deployment modes.**

## 🎯 Use Cases

- **Private VNet Observability**: Query logs from workspaces protected by Private Link—when public queries are blocked, deploy this server inside the VNet as a trusted query proxy
- **Incident Investigation**: Query logs from VMs, containers, and Azure resources during incidents
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
| `MCP_API_KEY` | No* | API key for authentication (required for remote deployment) |
| `MCP_API_KEY_HEADER` | No | Custom header name for API key (default: `X-API-Key`) |
| `AZURE_TENANT_ID` | No | Azure AD tenant ID (for service principal auth) |
| `AZURE_CLIENT_ID` | No | Service principal client ID |
| `AZURE_CLIENT_SECRET` | No | Service principal secret |

---

## 🌐 Remote Deployment (Azure Container Apps)

For production use with Azure SRE Agent or other remote MCP clients, deploy this server to Azure Container Apps.

### Prerequisites

- Azure CLI installed and logged in (`az login`)
- Docker (for local testing only)
- An Azure subscription

### Step 1: Create Azure Resources

```bash
# Set variables
RESOURCE_GROUP="log-analytics-mcp-rg"
LOCATION="eastus2"
ACR_NAME="yourregistryname"  # Must be globally unique
CONTAINER_APP_NAME="log-analytics-mcp"
WORKSPACE_ID="your-log-analytics-workspace-guid"
API_KEY=$(openssl rand -base64 32 | tr -d '/+=' | head -c 32)

# Create resource group
az group create --name $RESOURCE_GROUP --location $LOCATION

# Create container registry
az acr create --resource-group $RESOURCE_GROUP --name $ACR_NAME --sku Basic --admin-enabled true

# Create container apps environment
az containerapp env create \
  --name "${CONTAINER_APP_NAME}-env" \
  --resource-group $RESOURCE_GROUP \
  --location $LOCATION
```

### Step 2: Build and Push Container Image

```bash
# Build image in ACR (from the log-analytics-mcp-server directory)
az acr build --registry $ACR_NAME --image log-analytics-mcp:v1 .
```

### Step 3: Deploy Container App

```bash
# Get ACR credentials
ACR_PASSWORD=$(az acr credential show --name $ACR_NAME --query "passwords[0].value" -o tsv)

# Create container app with managed identity
az containerapp create \
  --name $CONTAINER_APP_NAME \
  --resource-group $RESOURCE_GROUP \
  --environment "${CONTAINER_APP_NAME}-env" \
  --image "${ACR_NAME}.azurecr.io/log-analytics-mcp:v1" \
  --target-port 8000 \
  --ingress external \
  --min-replicas 1 \
  --max-replicas 10 \
  --cpu 0.5 \
  --memory 1.0Gi \
  --registry-server "${ACR_NAME}.azurecr.io" \
  --registry-username $ACR_NAME \
  --registry-password "$ACR_PASSWORD" \
  --env-vars \
    "LOG_ANALYTICS_WORKSPACE_ID=$WORKSPACE_ID" \
    "MCP_API_KEY=$API_KEY" \
  --system-assigned

# Get the container app URL
FQDN=$(az containerapp show --name $CONTAINER_APP_NAME --resource-group $RESOURCE_GROUP --query "properties.configuration.ingress.fqdn" -o tsv)
echo "MCP Server URL: https://${FQDN}/mcp/"
echo "Health Check: https://${FQDN}/health"
echo "API Key: $API_KEY"
```

### Step 4: Grant Log Analytics Access

```bash
# Get managed identity principal ID
PRINCIPAL_ID=$(az containerapp show --name $CONTAINER_APP_NAME --resource-group $RESOURCE_GROUP --query "identity.principalId" -o tsv)

# Grant Log Analytics Reader role on the workspace
# Replace with your Log Analytics workspace resource ID
LA_RESOURCE_ID="/subscriptions/YOUR_SUB/resourceGroups/YOUR_RG/providers/Microsoft.OperationalInsights/workspaces/YOUR_WORKSPACE"

az role assignment create \
  --assignee $PRINCIPAL_ID \
  --role "Log Analytics Reader" \
  --scope $LA_RESOURCE_ID
```

### Step 5: Test the Deployment

```bash
# Test health endpoint
curl "https://${FQDN}/health"

# Test MCP initialization
curl -X POST "https://${FQDN}/mcp/" \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}'

# List available tools
curl -X POST "https://${FQDN}/mcp/" \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
```

### Remote Integration Examples

#### Azure SRE Agent

Configure in the SRE Agent portal:

| Setting | Value |
|---------|-------|
| **Name** | `LogAnalyticsMCP` |
| **Transport** | `Streamable HTTP` |
| **URL** | `https://your-app.azurecontainerapps.io/mcp/` |
| **Authentication** | `API Key` |
| **Header Name** | `X-API-Key` |
| **API Key** | Your generated API key |

#### Remote MCP Client Configuration

For any MCP client that supports HTTP transport:

```json
{
  "servers": {
    "log-analytics": {
      "type": "http",
      "url": "https://your-app.azurecontainerapps.io/mcp/",
      "headers": {
        "X-API-Key": "your-api-key"
      }
    }
  }
}
```

### Updating the Deployment

```bash
# Build new version
az acr build --registry $ACR_NAME --image log-analytics-mcp:v2 .

# Update container app
az containerapp update \
  --name $CONTAINER_APP_NAME \
  --resource-group $RESOURCE_GROUP \
  --image "${ACR_NAME}.azurecr.io/log-analytics-mcp:v2"
```

---

## 🔒 VNet Deployment (Private Link Scenarios)

When your Log Analytics workspace is protected by Private Link with `publicNetworkAccessForQuery: Disabled`, external queries are blocked. Deploy this MCP server **inside the VNet** to act as a trusted query proxy.

### Why This Matters

```
External Query → Log Analytics  ❌ BLOCKED by Private Link
VNet MCP → Log Analytics        ✅ ALLOWED via Private Endpoint  
SRE Agent → VNet MCP            ✅ HTTPS (Streamable HTTP)
```

### VNet-Integrated Deployment

```bash
# Create VNet-integrated Container Apps environment
az containerapp env create \
  --name vnet-test-env \
  --resource-group $RESOURCE_GROUP \
  --location eastus \
  --infrastructure-subnet-resource-id "/subscriptions/.../subnets/infrastructure"

# Create ACR (VNet environments can't pull from public registries)
az acr create --resource-group $RESOURCE_GROUP --name $ACR_NAME --sku Basic

# Build and push image to ACR
az acr build --registry $ACR_NAME --image log-analytics-mcp:latest .

# Deploy with Managed Identity
az containerapp create \
  --name log-analytics-mcp-vnet \
  --resource-group $RESOURCE_GROUP \
  --environment vnet-test-env \
  --image "${ACR_NAME}.azurecr.io/log-analytics-mcp:latest" \
  --target-port 8000 \
  --ingress external \
  --env-vars "LOG_ANALYTICS_WORKSPACE_ID=$WORKSPACE_ID" "MCP_API_KEY=$API_KEY" \
  --system-assigned \
  --registry-server "${ACR_NAME}.azurecr.io"

# Grant Log Analytics Reader role to Container App's Managed Identity
PRINCIPAL_ID=$(az containerapp show --name log-analytics-mcp-vnet --resource-group $RESOURCE_GROUP --query "identity.principalId" -o tsv)
az role assignment create \
  --assignee $PRINCIPAL_ID \
  --role "Log Analytics Reader" \
  --scope "/subscriptions/.../workspaces/$WORKSPACE_NAME"
```

### Testing Private Link Blocking

```bash
# Test from OUTSIDE VNet (should fail if Private Link is properly configured)
curl -X POST "https://log-analytics-mcp-outside.azurecontainerapps.io/mcp/" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "X-API-Key: $API_KEY" \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"list_tables"},"id":1}'

# Result: InsufficientAccessError - blocked by Private Link ❌

# Test from INSIDE VNet (should succeed)
curl -X POST "https://log-analytics-mcp-vnet.azurecontainerapps.io/mcp/" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "X-API-Key: $API_KEY" \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"list_tables"},"id":1}'

# Result: SUCCESS ✅ - tables returned
```

### Private Link Configuration

For complete query blocking, configure:

```bash
# 1. Create AMPLS with Private Only mode
az monitor private-link-scope create --name my-ampls --resource-group $RESOURCE_GROUP
az monitor private-link-scope update --name my-ampls --resource-group $RESOURCE_GROUP \
  --query-access PrivateOnly

# 2. Disable public query access on workspace
az monitor log-analytics workspace update \
  --resource-group $RESOURCE_GROUP \
  --workspace-name $WORKSPACE_NAME \
  --set properties.publicNetworkAccessForQuery=Disabled
```

---

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
