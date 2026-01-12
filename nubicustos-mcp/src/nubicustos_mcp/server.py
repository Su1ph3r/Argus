"""Nubicustos MCP Server - Main entry point."""

import atexit
import asyncio

from mcp.server.fastmcp import FastMCP

from .client import client
from .config import settings

# Create MCP server instance
mcp = FastMCP(
    settings.server_name,
    version=settings.server_version,
)


def _cleanup():
    """Clean up client resources on exit."""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            loop.create_task(client.close())
        else:
            loop.run_until_complete(client.close())
    except Exception:
        pass  # Best effort cleanup


atexit.register(_cleanup)


# Import and register tools
from .tools.scans import register_scan_tools
from .tools.findings import register_finding_tools
from .tools.attack_paths import register_attack_path_tools
from .tools.security import register_security_tools
from .tools.cloud import register_cloud_tools
from .tools.exports import register_export_tools
from .tools.system import register_system_tools

# Import and register resources
from .resources.data import register_resources

# Import and register prompts
from .prompts.scan_prompts import register_scan_prompts
from .prompts.analysis_prompts import register_analysis_prompts
from .prompts.ops_prompts import register_ops_prompts

# Register all components
register_scan_tools(mcp)
register_finding_tools(mcp)
register_attack_path_tools(mcp)
register_security_tools(mcp)
register_cloud_tools(mcp)
register_export_tools(mcp)
register_system_tools(mcp)
register_resources(mcp)
register_scan_prompts(mcp)
register_analysis_prompts(mcp)
register_ops_prompts(mcp)


def main():
    """Run the MCP server."""
    mcp.run()


if __name__ == "__main__":
    main()
