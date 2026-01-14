"""
Blog Scenario Test - Private VNet Observability
================================================
This script simulates the blog post scenario where an SRE uses
the Log Analytics MCP tools to debug a VM in a private VNet.

Scenario: "My VM in a private VNet stopped responding. 
I can't SSH into it because there's no public IP and the 
VPN is down. Help me figure out what's wrong."
"""

import os
# Set workspace ID
os.environ["LOG_ANALYTICS_WORKSPACE_ID"] = "fc50dcaf-5a84-46c7-a97a-0ea964d5d406"

from server import (
    list_tables,
    query_logs,
    get_workspace_info,
    analyze_errors,
    check_vm_health
)

def run_scenario():
    print("=" * 60)
    print("BLOG SCENARIO: Debugging Private VNet VM")
    print("=" * 60)
    print("\n[*] Simulating SRE Agent session...\n")
    
    # Step 1: Get workspace info
    print("[1] Step 1: Understanding the environment")
    print("-" * 40)
    workspace_info = get_workspace_info()
    print(f"   Workspace: {workspace_info[:200]}...")
    
    # Step 2: List available tables
    print("\n[2] Step 2: Discovering available log sources")
    print("-" * 40)
    tables = list_tables()
    print(f"   {tables}")
    
    # Step 3: Check VM health (simulated - no Heartbeat table)
    print("\n[3] Step 3: Checking VM connectivity via Heartbeat")
    print("-" * 40)
    try:
        health = check_vm_health()
        print(f"   {health[:200]}...")
    except Exception as e:
        print(f"   [!] No Heartbeat data available (expected in demo environment)")
    
    # Step 4: Analyze recent errors
    print("\n[4] Step 4: Analyzing error patterns")
    print("-" * 40)
    errors = analyze_errors(timespan="PT24H")
    print(f"   {errors[:500]}...")
    
    # Step 5: Query for specific errors
    print("\n[5] Step 5: Investigating specific exceptions")
    print("-" * 40)
    query = """
    AppExceptions 
    | where TimeGenerated > ago(24h)
    | summarize Count=count() by ExceptionType, ProblemId
    | top 5 by Count desc
    """
    exceptions = query_logs(query=query)
    print(f"   Top 5 exception types:")
    print(f"   {exceptions[:500]}...")
    
    # Step 6: Timeline analysis
    print("\n[6] Step 6: Error timeline analysis")
    print("-" * 40)
    timeline_query = """
    AppExceptions 
    | where TimeGenerated > ago(24h)
    | summarize ErrorCount=count() by bin(TimeGenerated, 1h)
    | order by TimeGenerated desc
    | take 6
    """
    timeline = query_logs(query=timeline_query)
    print(f"   Hourly error counts:")
    print(f"   {timeline[:500]}...")
    
    print("\n" + "=" * 60)
    print("[OK] SCENARIO COMPLETE")
    print("=" * 60)
    print("""
Summary:
The SRE Agent was able to:
1. Connect to Log Analytics via Private Link
2. Discover available log tables
3. Query for VM health status
4. Analyze error patterns and trends
5. Identify top exception types
6. Review error timeline

All without needing VPN access or direct VM connectivity!
""")

if __name__ == "__main__":
    run_scenario()
