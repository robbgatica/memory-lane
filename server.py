#!/usr/bin/env python3
"""
Memory Forensics MCP Server

Provides memory analysis capabilities via Volatility 3 through the MCP protocol.
Works with any MCP client (Claude Code, Claude Desktop, custom clients, etc.)
"""

import asyncio
import logging
from pathlib import Path
from typing import Any, Optional
import zipfile
import tempfile
import shutil
from datetime import datetime

from mcp.server.models import InitializationOptions
from mcp.server import NotificationOptions, Server
from mcp.server.stdio import stdio_server
from mcp.types import (
    Resource,
    Tool,
    TextContent,
    ImageContent,
    EmbeddedResource,
    LoggingLevel
)

from database import ForensicsDatabase
from volatility_handler import VolatilityHandler
from provenance import ProvenanceTracker
from hashing import get_or_calculate_hashes, format_hashes
from exporters import DataExporter
from timeline import TimelineGenerator
from anomaly_detector import AnomalyDetector
from extractors import create_extractor
from validation import DataValidator
from cleanup import (
    ManagedExtraction, cleanup_old_extractions, cleanup_all_extractions,
    get_disk_usage, list_extractions
)
from config import (
    DB_PATH, DUMPS_DIR, EXPORT_DIR, EXTRACTED_FILES_DIR, EXTRACTION_DIR,
    LLM_PROFILE, CURRENT_PROFILE_SETTINGS,
    EXTRACTION_RETENTION_HOURS, AUTO_CLEANUP_ON_STARTUP, DATA_DIR
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("memory-forensics-mcp")
logger.info(f"LLM Profile: {LLM_PROFILE}")
logger.info(f"Output format: {CURRENT_PROFILE_SETTINGS.get('format')}")

# Global database instance
db = ForensicsDatabase(DB_PATH)

# Global provenance tracker
provenance_tracker = ProvenanceTracker(db)

# Cache for VolatilityHandler instances
vol_handlers = {}


def get_dump_id(file_path: str) -> str:
    """Generate dump ID from filename"""
    return Path(file_path).stem


def extract_dump_if_needed(dump_path: Path) -> Path:
    """Extract memory dump from zip if necessary"""
    if dump_path.suffix.lower() == '.zip':
        logger.info(f"Extracting {dump_path.name}...")

        # Use persistent extraction directory instead of tmpfs
        import time
        dump_id = get_dump_id(str(dump_path))
        timestamp = int(time.time())
        temp_dir = EXTRACTION_DIR / f"memdump_{dump_id}_{timestamp}"
        temp_dir.mkdir(parents=True, exist_ok=True)

        with zipfile.ZipFile(dump_path, 'r') as zip_ref:
            # Extract all files
            zip_ref.extractall(temp_dir)

        # Find the actual memory dump file (usually .raw, .mem, .dmp, .vmem)
        for ext in ['.raw', '.mem', '.dmp', '.vmem', '.bin']:
            extracted_files = list(temp_dir.rglob(f'*{ext}'))
            if extracted_files:
                logger.info(f"Extracted to: {extracted_files[0]}")
                return extracted_files[0]

        # If no specific extension, return first file
        files = list(temp_dir.iterdir())
        if files:
            logger.info(f"Extracted to: {files[0]}")
            return files[0]

        raise ValueError(f"No memory dump found in {dump_path}")

    return dump_path


def get_volatility_handler(dump_id: str) -> Optional[VolatilityHandler]:
    """Get or create VolatilityHandler for a dump"""
    if dump_id in vol_handlers:
        return vol_handlers[dump_id]

    # Find the dump file
    for dump_file in DUMPS_DIR.iterdir():
        if get_dump_id(str(dump_file)) == dump_id:
            # Extract if needed
            actual_dump = extract_dump_if_needed(dump_file)

            # Create handler with dump_id and provenance tracking
            handler = VolatilityHandler(
                dump_path=actual_dump,
                dump_id=dump_id,
                provenance_tracker=provenance_tracker
            )
            vol_handlers[dump_id] = handler
            return handler

    return None


def adapt_description(description: str) -> str:
    """Adapt tool description based on LLM profile"""
    max_length = CURRENT_PROFILE_SETTINGS.get('max_description_length', 500)

    if len(description) <= max_length:
        return description

    # Truncate and add ellipsis
    return description[:max_length-3] + "..."


# Create the MCP server
server = Server("memory-forensics")


@server.list_resources()
async def handle_list_resources() -> list[Resource]:
    """List available memory dumps as resources"""
    dumps = await db.list_dumps()

    resources = []
    for dump in dumps:
        resources.append(Resource(
            uri=f"memdump://{dump['dump_id']}",
            name=f"Memory Dump: {dump['dump_id']}",
            description=f"Memory dump from {dump['file_path']} ({dump.get('os_type', 'Unknown OS')})",
            mimeType="application/x-memory-dump"
        ))

    return resources


@server.list_tools()
async def handle_list_tools() -> list[Tool]:
    """List available memory forensics tools"""
    return [
        Tool(
            name="list_dumps",
            description=adapt_description("List all available memory dumps for analysis"),
            inputSchema={
                "type": "object",
                "properties": {},
                "required": []
            }
        ),
        Tool(
            name="process_dump",
            description=adapt_description("Process a memory dump with Volatility 3 and extract artifacts (processes, network, etc.)"),
            inputSchema={
                "type": "object",
                "properties": {
                    "dump_id": {
                        "type": "string",
                        "description": "ID of the memory dump to process (from list_dumps)"
                    }
                },
                "required": ["dump_id"]
            }
        ),
        Tool(
            name="list_processes",
            description=adapt_description("List all processes from a memory dump"),
            inputSchema={
                "type": "object",
                "properties": {
                    "dump_id": {
                        "type": "string",
                        "description": "ID of the memory dump"
                    },
                    "suspicious_only": {
                        "type": "boolean",
                        "description": "Only show suspicious processes",
                        "default": False
                    }
                },
                "required": ["dump_id"]
            }
        ),
        Tool(
            name="analyze_process",
            description=adapt_description("Get detailed information about a specific process (command line, DLLs, network connections)"),
            inputSchema={
                "type": "object",
                "properties": {
                    "dump_id": {
                        "type": "string",
                        "description": "ID of the memory dump"
                    },
                    "pid": {
                        "type": "integer",
                        "description": "Process ID to analyze"
                    }
                },
                "required": ["dump_id", "pid"]
            }
        ),
        Tool(
            name="detect_code_injection",
            description=adapt_description("Detect potential code injection using malfind (unbacked executable memory regions)"),
            inputSchema={
                "type": "object",
                "properties": {
                    "dump_id": {
                        "type": "string",
                        "description": "ID of the memory dump"
                    },
                    "pid": {
                        "type": "integer",
                        "description": "Optional: only check specific process",
                        "default": None
                    }
                },
                "required": ["dump_id"]
            }
        ),
        Tool(
            name="network_analysis",
            description=adapt_description("Analyze network connections and correlate with processes"),
            inputSchema={
                "type": "object",
                "properties": {
                    "dump_id": {
                        "type": "string",
                        "description": "ID of the memory dump"
                    },
                    "remote_ip": {
                        "type": "string",
                        "description": "Optional: filter by remote IP address"
                    }
                },
                "required": ["dump_id"]
            }
        ),
        Tool(
            name="detect_hidden_processes",
            description=adapt_description("Find hidden processes by comparing psscan and pslist"),
            inputSchema={
                "type": "object",
                "properties": {
                    "dump_id": {
                        "type": "string",
                        "description": "ID of the memory dump"
                    }
                },
                "required": ["dump_id"]
            }
        ),
        Tool(
            name="get_process_tree",
            description=adapt_description("Get hierarchical process tree showing parent-child relationships"),
            inputSchema={
                "type": "object",
                "properties": {
                    "dump_id": {
                        "type": "string",
                        "description": "ID of the memory dump"
                    }
                },
                "required": ["dump_id"]
            }
        ),
        Tool(
            name="get_dump_metadata",
            description=adapt_description("Get detailed metadata about a memory dump including hashes, OS info, and processing statistics"),
            inputSchema={
                "type": "object",
                "properties": {
                    "dump_id": {
                        "type": "string",
                        "description": "ID of the memory dump"
                    }
                },
                "required": ["dump_id"]
            }
        ),
        Tool(
            name="export_data",
            description=adapt_description("Export forensic data in JSON, CSV, or HTML format"),
            inputSchema={
                "type": "object",
                "properties": {
                    "dump_id": {
                        "type": "string",
                        "description": "ID of the memory dump"
                    },
                    "format": {
                        "type": "string",
                        "description": "Export format: 'json', 'csv', or 'html'",
                        "enum": ["json", "csv", "html"]
                    },
                    "data_type": {
                        "type": "string",
                        "description": "Type of data to export (for csv): 'processes', 'network', 'memory_regions', or 'all' (for json/html)",
                        "default": "all"
                    },
                    "output_filename": {
                        "type": "string",
                        "description": "Optional output filename (will be placed in exports directory)",
                        "default": None
                    }
                },
                "required": ["dump_id", "format"]
            }
        ),
        Tool(
            name="get_command_history",
            description=adapt_description("View all Volatility commands executed for a dump (provenance/audit trail)"),
            inputSchema={
                "type": "object",
                "properties": {
                    "dump_id": {
                        "type": "string",
                        "description": "ID of the memory dump"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of commands to return",
                        "default": 50
                    }
                },
                "required": ["dump_id"]
            }
        ),
        Tool(
            name="generate_timeline",
            description=adapt_description("Generate chronological timeline of events from memory dump"),
            inputSchema={
                "type": "object",
                "properties": {
                    "dump_id": {
                        "type": "string",
                        "description": "ID of the memory dump"
                    },
                    "format": {
                        "type": "string",
                        "description": "Output format: 'summary' (display), 'json', 'csv', or 'text'",
                        "enum": ["summary", "json", "csv", "text"],
                        "default": "summary"
                    },
                    "suspicious_only": {
                        "type": "boolean",
                        "description": "Only include suspicious events",
                        "default": False
                    },
                    "output_filename": {
                        "type": "string",
                        "description": "Optional output filename for file exports",
                        "default": None
                    }
                },
                "required": ["dump_id"]
            }
        ),
        Tool(
            name="detect_anomalies",
            description=adapt_description("Detect suspicious process behavior (wrong parents, typosquatting, unusual paths)"),
            inputSchema={
                "type": "object",
                "properties": {
                    "dump_id": {
                        "type": "string",
                        "description": "ID of the memory dump"
                    }
                },
                "required": ["dump_id"]
            }
        ),
        Tool(
            name="health_check",
            description=adapt_description("Check data integrity and consistency for a processed memory dump"),
            inputSchema={
                "type": "object",
                "properties": {
                    "dump_id": {
                        "type": "string",
                        "description": "ID of the memory dump to validate"
                    }
                },
                "required": ["dump_id"]
            }
        ),
        Tool(
            name="extract_process",
            description=adapt_description("Extract detailed process information to JSON file"),
            inputSchema={
                "type": "object",
                "properties": {
                    "dump_id": {
                        "type": "string",
                        "description": "ID of the memory dump"
                    },
                    "pid": {
                        "type": "integer",
                        "description": "Process ID to extract"
                    }
                },
                "required": ["dump_id", "pid"]
            }
        ),
        Tool(
            name="cleanup_extractions",
            description=adapt_description("Clean up old memory dump extractions to free disk space"),
            inputSchema={
                "type": "object",
                "properties": {
                    "mode": {
                        "type": "string",
                        "description": "Cleanup mode: 'old' (remove extractions older than retention period), 'all' (remove all), 'list' (show extractions)",
                        "enum": ["old", "all", "list"],
                        "default": "old"
                    },
                    "dry_run": {
                        "type": "boolean",
                        "description": "If true, show what would be removed without actually deleting",
                        "default": False
                    }
                },
                "required": []
            }
        ),
        Tool(
            name="get_disk_usage",
            description=adapt_description("Get disk space usage statistics for the MCP server (database, exports, extractions)"),
            inputSchema={
                "type": "object",
                "properties": {},
                "required": []
            }
        )
    ]


@server.call_tool()
async def handle_call_tool(name: str, arguments: dict) -> list[TextContent]:
    """Handle tool execution"""

    try:
        if name == "list_dumps":
            # Check for available dumps in the dumps directory
            available_dumps = []
            for dump_file in DUMPS_DIR.iterdir():
                if dump_file.is_file() and dump_file.suffix in ['.zip', '.raw', '.mem', '.dmp', '.vmem']:
                    dump_id = get_dump_id(str(dump_file))
                    file_size = dump_file.stat().st_size

                    # Check if already in database
                    existing = await db.get_dump(dump_id)
                    if not existing:
                        # Register new dump
                        await db.add_dump(dump_id, str(dump_file), file_size)

                    available_dumps.append({
                        'dump_id': dump_id,
                        'file_name': dump_file.name,
                        'file_size_mb': round(file_size / (1024*1024), 2),
                        'status': existing.get('status', 'new') if existing else 'new'
                    })

            result = f"Found {len(available_dumps)} memory dumps:\n\n"
            for dump in available_dumps:
                result += f"- **{dump['dump_id']}**\n"
                result += f"  File: {dump['file_name']}\n"
                result += f"  Size: {dump['file_size_mb']} MB\n"
                result += f"  Status: {dump['status']}\n\n"

            return [TextContent(type="text", text=result)]

        elif name == "process_dump":
            dump_id = arguments["dump_id"]

            logger.info(f"Processing dump: {dump_id}")

            # Get Volatility handler
            vol = get_volatility_handler(dump_id)
            if not vol:
                return [TextContent(type="text", text=f"Error: Dump '{dump_id}' not found")]

            result = f"Processing memory dump: {dump_id}\n\n"

            # Extract processes
            result += "Extracting processes...\n"
            processes = await vol.list_processes()
            await db.add_processes(dump_id, processes)
            result += f"[OK] Found {len(processes)} processes\n\n"

            # Extract network connections
            result += "Extracting network connections...\n"
            connections = await vol.get_network_connections()
            # Clear old network data before inserting to prevent duplicates on reprocessing
            await db.clear_network_connections(dump_id)
            await db.add_network_connections(dump_id, connections)
            result += f"[OK] Found {len(connections)} network connections\n\n"

            # Detect code injection
            result += "Scanning for code injection...\n"
            suspicious_regions = await vol.detect_malfind()
            # Clear old memory region data before inserting to prevent duplicates on reprocessing
            await db.clear_memory_regions(dump_id)
            await db.add_memory_regions(dump_id, suspicious_regions)
            result += f"[OK] Found {len(suspicious_regions)} suspicious memory regions\n\n"

            # Detect hidden processes
            result += "Detecting hidden processes...\n"
            hidden_pids = await vol.detect_hidden_processes()

            # Mark hidden processes in database
            if hidden_pids:
                for pid in hidden_pids:
                    proc = await db.get_process_by_pid(dump_id, pid)
                    if proc:
                        proc['is_hidden'] = True
                        proc['is_suspicious'] = True
                        await db.add_processes(dump_id, [proc])

                result += f"[OK] Found {len(hidden_pids)} hidden processes: {hidden_pids}\n\n"
            else:
                result += "[OK] No hidden processes detected\n\n"

            # Update dump status
            dump = await db.get_dump(dump_id)
            if dump:
                await db.add_dump(dump_id, dump['file_path'], dump['file_size'], dump.get('os_type'))

            # Validate data integrity
            result += "Validating data integrity...\n"
            validator = DataValidator(db)

            # Compare Volatility results with database
            db_processes = await db.get_processes(dump_id)
            db_connections = await db.get_network_connections(dump_id)

            validation_warnings = await validator.compare_volatility_to_database(
                dump_id,
                {
                    'processes': len(processes),
                    'network_connections': len(connections),
                    'suspicious_memory_regions': len(suspicious_regions)
                },
                {
                    'processes': len(db_processes),
                    'network_connections': len(db_connections),
                    'suspicious_memory_regions': len(suspicious_regions)
                }
            )

            if validation_warnings:
                result += "\n**Data Integrity Warnings:**\n"
                for warning in validation_warnings:
                    result += f"- WARNING: {warning}\n"
                    logger.warning(f"[{dump_id}] {warning}")
            else:
                result += "[OK] All data validated successfully\n"

            result += "\n**Processing complete!** You can now use other tools to analyze the extracted data."

            return [TextContent(type="text", text=result)]

        elif name == "list_processes":
            dump_id = arguments["dump_id"]
            suspicious_only = arguments.get("suspicious_only", False)

            processes = await db.get_processes(dump_id, suspicious_only)

            if not processes:
                return [TextContent(type="text", text=f"No processes found. Run 'process_dump' first for dump: {dump_id}")]

            result = f"**Processes in {dump_id}**"
            if suspicious_only:
                result += " (suspicious only)"
            result += f"\n\nTotal: {len(processes)} processes\n\n"

            # Format as table
            result += "| PID | PPID | Name | Created | Flags |\n"
            result += "|-----|------|------|---------|-------|\n"

            for proc in processes:
                flags = []
                if proc.get('is_hidden'):
                    flags.append('HIDDEN')
                if proc.get('is_suspicious'):
                    flags.append('SUSPICIOUS')

                flag_str = ', '.join(flags) if flags else '-'

                result += f"| {proc['pid']} | {proc.get('ppid', '-')} | {proc.get('name', 'N/A')} | {proc.get('create_time', 'N/A')[:19]} | {flag_str} |\n"

            return [TextContent(type="text", text=result)]

        elif name == "analyze_process":
            dump_id = arguments["dump_id"]
            pid = arguments["pid"]

            # Get process info
            process = await db.get_process_by_pid(dump_id, pid)
            if not process:
                return [TextContent(type="text", text=f"Process {pid} not found in dump {dump_id}")]

            result = f"**Process Analysis: PID {pid}**\n\n"
            result += f"**Basic Information:**\n"
            result += f"- Name: {process.get('name', 'N/A')}\n"
            result += f"- Path: {process.get('path', 'N/A')}\n"
            result += f"- Parent PID: {process.get('ppid', 'N/A')}\n"
            result += f"- Created: {process.get('create_time', 'N/A')}\n"

            if process.get('is_hidden'):
                result += f"- [WARNING] **HIDDEN PROCESS** (not in standard process list)\n"
            if process.get('is_suspicious'):
                result += f"- [WARNING] **MARKED AS SUSPICIOUS**\n"

            result += "\n"

            # Get command line
            vol = get_volatility_handler(dump_id)
            if vol:
                cmdlines = await vol.get_cmdline(pid)
                if cmdlines:
                    result += f"**Command Line:**\n```\n{cmdlines[0].get('cmdline', 'N/A')}\n```\n\n"

                # Get DLLs
                result += "**Loaded DLLs:**\n"
                dlls = await vol.get_dlls(pid)
                if dlls:
                    for dll in dlls[:10]:  # Show first 10
                        result += f"- {dll.get('name', 'N/A')} @ {dll.get('base_address', 'N/A')}\n"
                    if len(dlls) > 10:
                        result += f"- ... and {len(dlls) - 10} more\n"
                else:
                    result += "- No DLLs found\n"
                result += "\n"

            # Get network connections
            connections = await db.get_network_connections(dump_id, pid)
            if connections:
                result += f"**Network Connections ({len(connections)}):**\n"
                for conn in connections:
                    result += f"- {conn.get('protocol', 'TCP')} {conn.get('local_addr')}:{conn.get('local_port')} → "
                    result += f"{conn.get('remote_addr')}:{conn.get('remote_port')} [{conn.get('state', 'N/A')}]\n"
                result += "\n"

            # Get suspicious memory regions
            regions = await db.get_suspicious_memory_regions(dump_id, pid)
            if regions:
                result += f"**[WARNING] Suspicious Memory Regions ({len(regions)}):**\n"
                for region in regions:
                    result += f"- Base: {region.get('base_address')} | Protection: {region.get('protection')} | "
                    result += f"Unbacked: {not region.get('is_file_backed')}\n"
                result += "\n**This may indicate code injection!**\n"

            return [TextContent(type="text", text=result)]

        elif name == "detect_code_injection":
            dump_id = arguments["dump_id"]
            target_pid = arguments.get("pid")

            # Get suspicious memory regions
            regions = await db.get_suspicious_memory_regions(dump_id, target_pid)

            if not regions:
                return [TextContent(type="text", text="No code injection detected. All processes appear clean.")]

            # Group by PID
            by_pid = {}
            for region in regions:
                pid = region['pid']
                if pid not in by_pid:
                    by_pid[pid] = []
                by_pid[pid].append(region)

            result = f"**Code Injection Detection Results**\n\n"
            result += f"Found suspicious memory regions in {len(by_pid)} process(es):\n\n"

            for pid, pid_regions in by_pid.items():
                # Get process name
                proc = await db.get_process_by_pid(dump_id, pid)
                proc_name = proc.get('name', 'Unknown') if proc else 'Unknown'

                result += f"**PID {pid} ({proc_name})** - {len(pid_regions)} suspicious region(s)\n"
                for region in pid_regions:
                    result += f"  - Base: {region.get('base_address')} | Protection: {region.get('protection')}\n"
                result += "\n"

            result += "**Recommendation:** Investigate these processes further. Unbacked executable memory often indicates:\n"
            result += "- Process hollowing\n"
            result += "- Reflective DLL injection\n"
            result += "- Shellcode injection\n"

            return [TextContent(type="text", text=result)]

        elif name == "network_analysis":
            dump_id = arguments["dump_id"]
            remote_ip = arguments.get("remote_ip")

            connections = await db.get_network_connections(dump_id)

            if not connections:
                return [TextContent(type="text", text="No network connections found.")]

            # Filter by IP if specified
            if remote_ip:
                connections = [c for c in connections if c.get('remote_addr') == remote_ip]
                if not connections:
                    return [TextContent(type="text", text=f"No connections found to {remote_ip}")]

            result = f"**Network Analysis**\n\n"
            result += f"Total connections: {len(connections)}\n\n"

            # Group by process
            by_pid = {}
            for conn in connections:
                pid = conn.get('pid')
                if pid not in by_pid:
                    by_pid[pid] = []
                by_pid[pid].append(conn)

            for pid, pid_conns in sorted(by_pid.items(), key=lambda x: (x[0] is None, x[0] or 0)):
                if pid:
                    proc = await db.get_process_by_pid(dump_id, pid)
                    proc_name = proc.get('name', 'Unknown') if proc else 'Unknown'
                    result += f"**PID {pid} ({proc_name})** - {len(pid_conns)} connection(s)\n"
                else:
                    result += f"**Unknown PID** - {len(pid_conns)} connection(s)\n"

                for conn in pid_conns:
                    result += f"  - {conn.get('protocol', 'TCP')} {conn.get('local_addr')}:{conn.get('local_port')} → "
                    result += f"{conn.get('remote_addr')}:{conn.get('remote_port')} [{conn.get('state', 'N/A')}]\n"
                result += "\n"

            return [TextContent(type="text", text=result)]

        elif name == "detect_hidden_processes":
            dump_id = arguments["dump_id"]

            vol = get_volatility_handler(dump_id)
            if not vol:
                return [TextContent(type="text", text=f"Error: Dump '{dump_id}' not found")]

            hidden_pids = await vol.detect_hidden_processes()

            if not hidden_pids:
                return [TextContent(type="text", text="No hidden processes detected. All processes appear in the standard process list.")]

            result = f"**[WARNING] Hidden Process Detection**\n\n"
            result += f"Found {len(hidden_pids)} hidden process(es):\n\n"

            for pid in hidden_pids:
                proc = await db.get_process_by_pid(dump_id, pid)
                if proc:
                    result += f"- PID {pid}: {proc.get('name', 'Unknown')}\n"
                else:
                    result += f"- PID {pid}: (process details not available)\n"

            result += "\n**Explanation:** These processes appear in memory scans but not in the standard process list, "
            result += "which may indicate rootkit activity or process hiding techniques.\n"

            return [TextContent(type="text", text=result)]

        elif name == "get_process_tree":
            dump_id = arguments["dump_id"]

            processes = await db.get_processes(dump_id)
            if not processes:
                return [TextContent(type="text", text=f"No processes found. Run 'process_dump' first.")]

            # Build process tree
            proc_map = {p['pid']: p for p in processes}
            children_map = {}
            roots = []

            for proc in processes:
                ppid = proc.get('ppid')
                if ppid and ppid in proc_map:
                    if ppid not in children_map:
                        children_map[ppid] = []
                    children_map[ppid].append(proc['pid'])
                else:
                    roots.append(proc['pid'])

            def format_tree(pid, indent=0):
                proc = proc_map.get(pid)
                if not proc:
                    return ""

                prefix = "  " * indent
                flags = []
                if proc.get('is_hidden'):
                    flags.append('HIDDEN')
                if proc.get('is_suspicious'):
                    flags.append('SUSP')

                flag_str = f" [{', '.join(flags)}]" if flags else ""
                line = f"{prefix}├─ {pid}: {proc.get('name', 'N/A')}{flag_str}\n"

                # Add children
                if pid in children_map:
                    for child_pid in children_map[pid]:
                        line += format_tree(child_pid, indent + 1)

                return line

            result = f"**Process Tree for {dump_id}**\n\n```\n"
            for root_pid in sorted(roots):
                result += format_tree(root_pid)
            result += "```\n"

            return [TextContent(type="text", text=result)]

        elif name == "get_dump_metadata":
            dump_id = arguments["dump_id"]

            # Get dump info
            dump = await db.get_dump(dump_id)
            if not dump:
                return [TextContent(type="text", text=f"Dump '{dump_id}' not found")]

            result = f"**Memory Dump Metadata**\n\n"

            # File information
            result += "**File Information:**\n"
            result += f"- Dump ID: {dump_id}\n"
            result += f"- File Path: {dump.get('file_path', 'N/A')}\n"
            result += f"- File Size: {dump.get('file_size', 0) / (1024*1024):.2f} MB\n"

            # Get or calculate hashes
            dump_path = Path(dump['file_path'])
            if dump_path.suffix == '.zip':
                # For zip files, find the actual dump
                dump_path = extract_dump_if_needed(dump_path)

            hashes = await get_or_calculate_hashes(db, dump_id, dump_path)

            result += "\n" + format_hashes(hashes)

            # OS information
            if dump.get('os_type'):
                result += f"\n**Operating System:**\n"
                result += f"- OS Type: {dump.get('os_type', 'Unknown')}\n"

            # Processing status
            result += f"\n**Processing Status:**\n"
            result += f"- Status: {dump.get('status', 'new')}\n"
            result += f"- Last Processed: {dump.get('last_processed', 'Never')}\n"

            # Get command statistics
            stats = await db.get_command_stats(dump_id)
            if stats and stats.get('total_commands', 0) > 0:
                result += f"- Commands Executed: {stats.get('total_commands', 0)}\n"
                result += f"- Average Execution Time: {int(stats.get('avg_execution_time', 0))} ms\n"

                # Count suspicious findings
                processes = await db.get_processes(dump_id)
                suspicious_procs = sum(1 for p in processes if p.get('is_suspicious'))
                regions = await db.get_suspicious_memory_regions(dump_id)

                if suspicious_procs > 0 or len(regions) > 0:
                    result += f"- Suspicious Findings: {suspicious_procs} processes, {len(regions)} memory regions\n"

            return [TextContent(type="text", text=result)]

        elif name == "export_data":
            dump_id = arguments["dump_id"]
            export_format = arguments["format"]
            data_type = arguments.get("data_type", "all")
            output_filename = arguments.get("output_filename")

            # Generate filename if not provided
            if not output_filename:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                if export_format == "csv":
                    output_filename = f"{dump_id}_{data_type}_{timestamp}.csv"
                elif export_format == "json":
                    output_filename = f"{dump_id}_{timestamp}.json"
                else:  # html
                    output_filename = f"{dump_id}_report_{timestamp}.html"

            output_path = EXPORT_DIR / output_filename

            # Create exporter
            exporter = DataExporter(db)

            # Export data
            try:
                if export_format == "json":
                    data_types = [data_type] if data_type != "all" else ["processes", "network", "memory_regions"]
                    stats = await exporter.export_json(dump_id, output_path, data_types=data_types)
                elif export_format == "csv":
                    if data_type == "all":
                        return [TextContent(type="text", text="Error: CSV format requires a specific data_type (processes, network, or memory_regions)")]
                    stats = await exporter.export_csv(dump_id, data_type, output_path)
                elif export_format == "html":
                    stats = await exporter.export_html(dump_id, output_path)
                else:
                    return [TextContent(type="text", text=f"Unknown format: {export_format}")]

                result = f"**Data Export Complete**\n\n"
                result += f"Format: {stats['format']}\n"
                result += f"Output: {stats['output_path']}\n"
                result += f"Size: {stats.get('file_size', 0) / 1024:.2f} KB\n"
                if 'total_records' in stats:
                    result += f"Records: {stats['total_records']}\n"

                return [TextContent(type="text", text=result)]

            except Exception as e:
                logger.error(f"Export failed: {e}", exc_info=True)
                return [TextContent(type="text", text=f"Export failed: {str(e)}")]

        elif name == "get_command_history":
            dump_id = arguments["dump_id"]
            limit = arguments.get("limit", 50)

            # Get provenance summary
            summary = await provenance_tracker.get_provenance_summary(dump_id)

            return [TextContent(type="text", text=summary)]

        elif name == "generate_timeline":
            dump_id = arguments["dump_id"]
            format_type = arguments.get("format", "summary")
            suspicious_only = arguments.get("suspicious_only", False)
            output_filename = arguments.get("output_filename")

            # Create timeline generator
            timeline_gen = TimelineGenerator(db)

            if format_type == "summary":
                # Display summary
                summary = await timeline_gen.get_timeline_summary(dump_id)
                return [TextContent(type="text", text=summary)]
            else:
                # Export to file
                if not output_filename:
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    output_filename = f"{dump_id}_timeline_{timestamp}.{format_type}"

                output_path = EXPORT_DIR / output_filename

                try:
                    if format_type == "json":
                        stats = await timeline_gen.export_timeline_json(
                            dump_id, output_path, suspicious_only=suspicious_only
                        )
                    elif format_type == "csv":
                        stats = await timeline_gen.export_timeline_csv(
                            dump_id, output_path, suspicious_only=suspicious_only
                        )
                    elif format_type == "text":
                        stats = await timeline_gen.export_timeline_text(
                            dump_id, output_path, suspicious_only=suspicious_only
                        )
                    else:
                        return [TextContent(type="text", text=f"Unknown format: {format_type}")]

                    result = f"**Timeline Export Complete**\n\n"
                    result += f"Format: {stats['format']}\n"
                    result += f"Output: {stats['output_path']}\n"
                    result += f"Events: {stats['event_count']}\n"
                    result += f"Size: {stats.get('file_size', 0) / 1024:.2f} KB\n"

                    return [TextContent(type="text", text=result)]

                except Exception as e:
                    logger.error(f"Timeline export failed: {e}", exc_info=True)
                    return [TextContent(type="text", text=f"Timeline export failed: {str(e)}")]

        elif name == "detect_anomalies":
            dump_id = arguments["dump_id"]

            # Create anomaly detector
            detector = AnomalyDetector(db)

            # Detect anomalies (returns list of anomaly dicts)
            anomalies = await detector.detect_anomalies(dump_id)

            # Extract PIDs of suspicious processes and persist to database
            suspicious_pids = set()
            for anomaly in anomalies:
                if 'pid' in anomaly:
                    suspicious_pids.add(anomaly['pid'])
                # For duplicate instances, add all PIDs
                if 'pids' in anomaly:
                    suspicious_pids.update(anomaly['pids'])

            # Mark processes as suspicious in the database
            if suspicious_pids:
                await db.mark_processes_suspicious(dump_id, list(suspicious_pids))
                logger.info(f"Marked {len(suspicious_pids)} processes as suspicious in database")

            # Get anomaly report
            report = await detector.get_anomaly_report(dump_id)

            return [TextContent(type="text", text=report)]

        elif name == "health_check":
            dump_id = arguments["dump_id"]

            # Create validator
            validator = DataValidator(db)

            # Run integrity check
            validation_result = await validator.validate_dump_integrity(dump_id)

            # Format result
            result = f"**Data Integrity Check - {dump_id}**\n\n"

            if validation_result['valid']:
                result += "Status: HEALTHY\n\n"
            else:
                result += "Status: ISSUES FOUND\n\n"

            # Show statistics
            stats = validation_result.get('stats', {})
            result += "**Statistics:**\n"
            result += f"- Total Commands: {stats.get('total_commands', 0)}\n"
            result += f"- Failed Commands: {stats.get('failed_commands', 0)}\n"
            result += f"- Process Count: {stats.get('process_count', 0)}\n"
            result += f"- Network Connection Count: {stats.get('network_count', 0)}\n\n"

            # Show issues
            if validation_result.get('issues'):
                result += "**Critical Issues:**\n"
                for issue in validation_result['issues']:
                    result += f"- ERROR: {issue}\n"
                result += "\n"

            # Show warnings
            if validation_result.get('warnings'):
                result += "**Warnings:**\n"
                for warning in validation_result['warnings']:
                    result += f"- WARNING: {warning}\n"
                result += "\n"

            if not validation_result.get('issues') and not validation_result.get('warnings'):
                result += "No issues or warnings detected. Data appears consistent.\n"

            return [TextContent(type="text", text=result)]

        elif name == "extract_process":
            dump_id = arguments["dump_id"]
            pid = arguments["pid"]

            # Get volatility handler
            vol = get_volatility_handler(dump_id)
            if not vol:
                return [TextContent(type="text", text=f"Error: Dump '{dump_id}' not found")]

            # Create extractor
            extractor = await create_extractor(dump_id, vol, db)

            try:
                # Extract process info
                info = await extractor.extract_process_info(pid, EXTRACTED_FILES_DIR)

                result = f"**Process Extraction Complete**\n\n"
                result += f"Process ID: {info['pid']}\n"
                result += f"Output: {info['output_path']}\n"
                result += f"Size: {info['file_size'] / 1024:.2f} KB\n"
                result += f"SHA256: {info['sha256']}\n\n"
                result += f"**Extracted Information:**\n"
                result += f"- Loaded DLLs: {info['dll_count']}\n"
                result += f"- Network Connections: {info['connection_count']}\n"
                result += f"- Suspicious Memory Regions: {info['suspicious_region_count']}\n\n"
                result += f"File contains comprehensive JSON with all process details.\n"

                return [TextContent(type="text", text=result)]

            except Exception as e:
                logger.error(f"Process extraction failed: {e}", exc_info=True)
                return [TextContent(type="text", text=f"Process extraction failed: {str(e)}")]

        elif name == "cleanup_extractions":
            mode = arguments.get("mode", "old")
            dry_run = arguments.get("dry_run", False)

            try:
                if mode == "list":
                    # List all extractions
                    extractions = list_extractions(EXTRACTION_DIR)

                    if not extractions:
                        return [TextContent(type="text", text="No extractions found.")]

                    result = f"**Current Extractions**\n\n"
                    result += f"Found {len(extractions)} extraction(s):\n\n"

                    for extraction in extractions:
                        result += f"**{extraction['name']}**\n"
                        result += f"- Size: {extraction['size_gb']:.2f} GB\n"
                        result += f"- Created: {extraction['created']}\n"
                        result += f"- Age: {extraction['age_hours']:.1f} hours\n\n"

                    return [TextContent(type="text", text=result)]

                elif mode == "all":
                    # Remove all extractions
                    stats = cleanup_all_extractions(EXTRACTION_DIR)

                    result = f"**Cleanup Complete**\n\n"
                    result += f"Removed: {stats['removed_count']} extraction(s)\n"
                    result += f"Freed: {stats['freed_gb']:.2f} GB\n"

                    if stats.get('errors'):
                        result += f"\n**Errors:**\n"
                        for error in stats['errors']:
                            result += f"- {error}\n"

                    return [TextContent(type="text", text=result)]

                else:  # mode == "old"
                    # Remove old extractions
                    stats = cleanup_old_extractions(
                        EXTRACTION_DIR,
                        retention_hours=EXTRACTION_RETENTION_HOURS,
                        dry_run=dry_run
                    )

                    if dry_run:
                        result = f"**Cleanup Preview (Dry Run)**\n\n"
                    else:
                        result = f"**Cleanup Complete**\n\n"

                    result += f"Retention period: {EXTRACTION_RETENTION_HOURS} hours\n"
                    result += f"Removed: {stats['removed_count']} extraction(s)\n"
                    result += f"Freed: {stats['freed_gb']:.2f} GB\n"

                    if dry_run and stats['removed_count'] > 0:
                        result += f"\nRun with dry_run=false to actually remove these files.\n"

                    if stats.get('errors'):
                        result += f"\n**Errors:**\n"
                        for error in stats['errors']:
                            result += f"- {error}\n"

                    return [TextContent(type="text", text=result)]

            except Exception as e:
                logger.error(f"Cleanup failed: {e}", exc_info=True)
                return [TextContent(type="text", text=f"Cleanup failed: {str(e)}")]

        elif name == "get_disk_usage":
            try:
                stats = get_disk_usage(DATA_DIR, EXTRACTION_DIR)

                result = f"**Disk Usage Statistics**\n\n"
                result += f"**Database:**\n"
                result += f"- Size: {stats['database_size_mb']:.2f} MB\n"
                result += f"- Location: {stats['data_dir']}/artifacts.db\n\n"

                result += f"**Exports:**\n"
                result += f"- Size: {stats['exports_size_mb']:.2f} MB\n"
                result += f"- Location: {stats['data_dir']}/exports\n\n"

                result += f"**Extractions:**\n"
                result += f"- Size: {stats['extractions_size_gb']:.2f} GB\n"
                result += f"- Count: {stats['extractions_count']}\n"
                result += f"- Location: {stats['extraction_dir']}\n\n"

                result += f"**Total:**\n"
                result += f"- Size: {stats['total_size_gb']:.2f} GB\n"

                # Add recommendation if extractions are large
                if stats['extractions_size_gb'] > 5.0:
                    result += f"\n**Recommendation:** Extractions are using {stats['extractions_size_gb']:.2f} GB. "
                    result += f"Consider running cleanup_extractions to free space.\n"

                return [TextContent(type="text", text=result)]

            except Exception as e:
                logger.error(f"Failed to get disk usage: {e}", exc_info=True)
                return [TextContent(type="text", text=f"Failed to get disk usage: {str(e)}")]

        else:
            return [TextContent(type="text", text=f"Unknown tool: {name}")]

    except Exception as e:
        logger.error(f"Error executing tool {name}: {e}", exc_info=True)
        return [TextContent(type="text", text=f"Error: {str(e)}")]


async def main():
    """Main entry point for the MCP server"""
    # Initialize database
    await db.initialize()
    logger.info("Memory Forensics MCP Server starting...")
    logger.info(f"Database: {DB_PATH}")
    logger.info(f"Dumps directory: {DUMPS_DIR}")

    # Clean up old extractions on startup
    if AUTO_CLEANUP_ON_STARTUP:
        try:
            stats = cleanup_old_extractions(
                EXTRACTION_DIR,
                retention_hours=EXTRACTION_RETENTION_HOURS,
                dry_run=False
            )
            if stats['removed_count'] > 0:
                logger.info(
                    f"Startup cleanup: Removed {stats['removed_count']} old extraction(s), "
                    f"freed {stats['freed_gb']:.2f} GB"
                )
        except Exception as e:
            logger.warning(f"Startup cleanup failed: {e}")

    # Run the server
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="memory-forensics",
                server_version="0.1.0",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={}
                )
            )
        )


if __name__ == "__main__":
    asyncio.run(main())
