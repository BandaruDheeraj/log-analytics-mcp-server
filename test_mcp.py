#!/usr/bin/env python3
"""Test script for Log Analytics MCP Server."""

import json
import os

# Ensure workspace ID is set
os.environ.setdefault('LOG_ANALYTICS_WORKSPACE_ID', 'fc50dcaf-5a84-46c7-a97a-0ea964d5d406')

from server import mcp, list_tables, query_logs, get_workspace_info

print('=' * 60)
print('LOG ANALYTICS MCP SERVER - VALIDATION TEST')
print('=' * 60)
print()

# Test 1: MCP Server Info
print('[1] MCP Server Info:')
print(f'    Server name: {mcp.name}')
print(f'    Tools registered: {len(mcp._tool_manager._tools)}')
for name in mcp._tool_manager._tools.keys():
    print(f'      - {name}')
print()

# Test 2: List tables
print('[2] Testing list_tables()...')
try:
    result = list_tables()
    if 'columns' in result:
        print('    ✅ SUCCESS - Retrieved table list')
        # Extract table names
        clean_result = result.replace('Available tables in workspace:\n', '')
        data = json.loads(clean_result)
        if data and data[0].get('rows'):
            tables = [r.get('$table', 'unknown') for r in data[0]['rows']]
            print(f'    Found {len(tables)} tables: {tables}')
    else:
        print(f'    ⚠️  Result: {result[:200]}')
except Exception as e:
    print(f'    ❌ FAILED: {e}')
print()

# Test 3: Query logs
print('[3] Testing query_logs()...')
try:
    result = query_logs('AppExceptions | summarize TotalErrors=count()', timespan='P7D')
    if 'row_count' in result:
        data = json.loads(result)
        if data and data[0].get('rows'):
            count = data[0]['rows'][0].get('TotalErrors', 0)
            print(f'    ✅ SUCCESS - Found {count} total errors in AppExceptions')
        else:
            print('    ✅ SUCCESS - Query executed (no data)')
    else:
        print(f'    ⚠️  Result: {result[:200]}')
except Exception as e:
    print(f'    ❌ FAILED: {e}')
print()

# Test 4: Get workspace info
print('[4] Testing get_workspace_info()...')
try:
    result = get_workspace_info()
    if 'Workspace data usage' in result:
        print('    ✅ SUCCESS - Retrieved workspace info')
    else:
        print(f'    ⚠️  Result: {result[:200]}')
except Exception as e:
    print(f'    ❌ FAILED: {e}')
print()

print('=' * 60)
print('VALIDATION COMPLETE')
print('=' * 60)
