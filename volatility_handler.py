"""Volatility 3 integration for memory analysis"""
import sys
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional
import json

# Add Volatility 3 to path
from config import VOLATILITY_PATH
sys.path.insert(0, str(VOLATILITY_PATH))

try:
    from volatility3.framework import contexts, automagic, plugins, exceptions
    from volatility3.framework.configuration import requirements
    from volatility3.cli import text_renderer
    import volatility3.plugins
except ImportError as e:
    print(f"Error importing Volatility 3: {e}")
    print(f"Make sure Volatility 3 is installed at: {VOLATILITY_PATH}")
    sys.exit(1)

logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger(__name__)


class VolatilityHandler:
    """Handles interactions with Volatility 3 framework"""

    def __init__(self, dump_path: Path, dump_id: str = None, provenance_tracker=None):
        self.dump_path = dump_path
        self.dump_id = dump_id or Path(dump_path).stem
        self.provenance_tracker = provenance_tracker
        self.context = None
        self.automagics = None

    def _build_context(self):
        """Build Volatility context for the memory dump"""
        if self.context:
            return self.context

        # Create a context
        self.context = contexts.Context()

        # Set the memory layer
        single_location = f"file://{self.dump_path}"
        self.context.config['automagic.LayerStacker.single_location'] = single_location

        # Build automagic - use all available automagics without filtering
        # (filtering by plugin would require knowing the plugin beforehand)
        self.automagics = automagic.available(self.context)

        return self.context

    async def run_plugin(self, plugin_class, **kwargs) -> List[Dict[str, Any]]:
        """Run a Volatility plugin and return results as list of dicts"""
        import time
        from volatility3.framework import renderers

        start_time = time.time()
        plugin_name = f"{plugin_class.__module__}.{plugin_class.__name__}"
        success = True
        error_message = None
        results = []

        try:
            context = self._build_context()

            # Construct the plugin
            constructed = plugins.construct_plugin(
                context,
                self.automagics,
                plugin_class,
                "plugins",
                None,
                None
            )

            # Run the plugin - returns a TreeGrid
            treegrid = constructed.run()

            # Collect results by visiting each node
            def visitor(node, accumulator):
                # Create dict from node values and column names
                row_dict = {}
                for column_index, column in enumerate(treegrid.columns):
                    value = node.values[column_index]

                    # Handle UnreadableValue objects from Volatility
                    if isinstance(value, renderers.UnreadableValue):
                        row_dict[column.name] = None
                    # Convert non-primitive types to strings
                    elif hasattr(value, '__iter__') and not isinstance(value, (str, bytes)):
                        row_dict[column.name] = str(value)
                    else:
                        row_dict[column.name] = value

                accumulator.append(row_dict)
                return accumulator

            # Populate and visit all nodes
            treegrid.populate(visitor, results)

        except exceptions.VolatilityException as e:
            logger.error(f"Volatility error running {plugin_class.__name__}: {e}", exc_info=True)
            success = False
            error_message = str(e)
        except Exception as e:
            logger.error(f"Unexpected error running {plugin_class.__name__}: {e}", exc_info=True)
            success = False
            error_message = str(e)

        # Calculate execution time
        execution_time_ms = int((time.time() - start_time) * 1000)

        # Log command execution if provenance tracker is available
        if self.provenance_tracker:
            try:
                await self.provenance_tracker.log_command(
                    dump_id=self.dump_id,
                    plugin_name=plugin_name,
                    dump_path=self.dump_path,
                    parameters=kwargs if kwargs else None,
                    execution_time_ms=execution_time_ms,
                    row_count=len(results),
                    success=success,
                    error=error_message
                )
            except Exception as log_error:
                logger.warning(f"Failed to log command: {log_error}")

        return results

    async def list_processes(self) -> List[Dict[str, Any]]:
        """Run windows.pslist plugin"""
        try:
            from volatility3.plugins.windows import pslist
            results = await self.run_plugin(pslist.PsList)

            # Parse and normalize
            processes = []
            for proc in results:
                processes.append({
                    'pid': proc.get('PID'),
                    'ppid': proc.get('PPID'),
                    'name': proc.get('ImageFileName'),
                    'path': None,  # Not in pslist
                    'cmdline': None,  # Need cmdline plugin
                    'create_time': str(proc.get('CreateTime', '')),
                    'exit_time': str(proc.get('ExitTime', '')),
                    'is_hidden': False,
                    'is_suspicious': False
                })

            return processes
        except Exception as e:
            logger.error(f"Error in list_processes: {e}", exc_info=True)
            return []

    async def get_process_tree(self) -> List[Dict[str, Any]]:
        """Run windows.pstree plugin"""
        try:
            from volatility3.plugins.windows import pstree
            results = await self.run_plugin(pstree.PsTree)

            # Similar parsing as pslist
            processes = []
            for proc in results:
                processes.append({
                    'pid': proc.get('PID'),
                    'ppid': proc.get('PPID'),
                    'name': proc.get('ImageFileName'),
                    'create_time': str(proc.get('CreateTime', '')),
                })

            return processes
        except Exception as e:
            logger.error(f"Error in get_process_tree: {e}", exc_info=True)
            return []

    async def get_network_connections(self) -> List[Dict[str, Any]]:
        """Run windows.netscan plugin"""
        try:
            from volatility3.plugins.windows import netscan
        except ImportError as e:
            logger.critical(f"CRITICAL: Missing dependency for network analysis: {e}")
            logger.critical("Install missing dependencies: pip install pefile")
            raise ImportError(f"Network analysis unavailable - missing dependency: {e}") from e

        try:
            results = await self.run_plugin(netscan.NetScan)

            connections = []
            for conn in results:
                connections.append({
                    'pid': conn.get('PID'),
                    'local_addr': str(conn.get('LocalAddr', '')),
                    'local_port': conn.get('LocalPort'),
                    'remote_addr': str(conn.get('ForeignAddr', '')),
                    'remote_port': conn.get('ForeignPort'),
                    'state': str(conn.get('State', '')),
                    'protocol': str(conn.get('Proto', ''))  # Fixed: 'Proto' not 'Protocol'
                })

            return connections
        except Exception as e:
            logger.error(f"Error in get_network_connections: {e}", exc_info=True)
            return []

    async def detect_malfind(self) -> List[Dict[str, Any]]:
        """Run windows.malfind plugin to detect injected code"""
        try:
            from volatility3.plugins.windows import malfind
            results = await self.run_plugin(malfind.Malfind)

            regions = []
            for item in results:
                regions.append({
                    'pid': item.get('PID'),
                    'process': item.get('Process'),
                    'base_address': hex(item.get('Start', 0)),
                    'protection': item.get('Protection'),
                    'is_file_backed': False,  # malfind finds unbacked regions
                    'backing_file': None,
                    'is_suspicious': True,  # malfind only returns suspicious regions
                    'size': None  # Not directly in malfind output
                })

            return regions
        except Exception as e:
            logger.error(f"Error in detect_malfind: {e}", exc_info=True)
            return []

    async def get_cmdline(self, pid: Optional[int] = None) -> List[Dict[str, Any]]:
        """Run windows.cmdline plugin"""
        try:
            from volatility3.plugins.windows import cmdline
            results = await self.run_plugin(cmdline.CmdLine)

            cmdlines = []
            for item in results:
                item_pid = item.get('PID')
                if pid is None or item_pid == pid:
                    cmdlines.append({
                        'pid': item_pid,
                        'process': item.get('Process'),
                        'cmdline': item.get('Args')
                    })

            return cmdlines
        except Exception as e:
            logger.error(f"Error in get_cmdline: {e}", exc_info=True)
            return []

    async def get_dlls(self, pid: int) -> List[Dict[str, Any]]:
        """Run windows.dlllist plugin for specific PID"""
        try:
            from volatility3.plugins.windows import dlllist
            results = await self.run_plugin(dlllist.DllList)

            dlls = []
            for item in results:
                if item.get('PID') == pid:
                    dlls.append({
                        'pid': pid,
                        'base_address': hex(item.get('Base', 0)),
                        'size': item.get('Size'),
                        'name': item.get('Name'),
                        'path': item.get('Path')
                    })

            return dlls
        except Exception as e:
            logger.error(f"Error in get_dlls: {e}", exc_info=True)
            return []

    async def detect_hidden_processes(self) -> List[int]:
        """Compare psscan and pslist to find hidden processes"""
        try:
            from volatility3.plugins.windows import pslist, psscan

            # Get visible processes
            visible = await self.run_plugin(pslist.PsList)
            visible_pids = {p.get('PID') for p in visible if p.get('PID')}

            # Get all processes (including hidden)
            all_procs = await self.run_plugin(psscan.PsScan)
            all_pids = {p.get('PID') for p in all_procs if p.get('PID')}

            # Hidden processes are in psscan but not pslist
            hidden_pids = all_pids - visible_pids

            return list(hidden_pids)

        except Exception as e:
            logger.error(f"Error detecting hidden processes: {e}", exc_info=True)
            return []
