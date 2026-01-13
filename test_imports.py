#!/usr/bin/env python3
"""Test script to verify MCP imports work correctly."""

print("Testing MCP imports...")

try:
    import mcp
    print(f"✓ mcp version: {mcp.__version__ if hasattr(mcp, '__version__') else 'unknown'}")
except Exception as e:
    print(f"✗ Failed to import mcp: {e}")

try:
    from mcp import Server
    print("✓ mcp.Server imported successfully (FastMCP style)")
except Exception as e:
    print(f"✗ mcp.Server: {e}")

try:
    from mcp.server import Server
    print("✓ mcp.server.Server imported")
except Exception as e:
    print(f"✗ mcp.server.Server: {e}")

try:
    from mcp.server.sse import SseServerTransport
    print("✓ SseServerTransport imported")
except Exception as e:
    print(f"✗ SseServerTransport: {e}")

try:
    from mcp.server.stdio import stdio_server
    print("✓ stdio_server imported")
except Exception as e:
    print(f"✗ stdio_server: {e}")

# Check for FastMCP pattern
try:
    from mcp.server.fastmcp import FastMCP
    print("✓ FastMCP imported (new API)")
except Exception as e:
    print(f"✗ FastMCP: {e}")

# List what's available in mcp
print("\nAvailable in mcp module:")
import mcp
for name in sorted(dir(mcp)):
    if not name.startswith('_'):
        print(f"  - {name}")
