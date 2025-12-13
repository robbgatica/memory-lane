"""Data validation and integrity checking for memory forensics artifacts"""
from typing import Dict, List, Any
from database import ForensicsDatabase


class DataValidator:
    """Validates consistency between Volatility results and database storage"""

    def __init__(self, db: ForensicsDatabase):
        self.db = db

    async def validate_dump_integrity(self, dump_id: str) -> Dict[str, Any]:
        """
        Check if dump data is complete and consistent

        Args:
            dump_id: Dump identifier

        Returns:
            Dict with 'valid' (bool) and 'issues' (list of strings)
        """
        issues = []
        warnings = []

        # Check if dump exists
        dump = await self.db.get_dump(dump_id)
        if not dump:
            issues.append(f"Dump '{dump_id}' not found in database")
            return {"valid": False, "issues": issues, "warnings": warnings}

        # Check basic data exists
        processes = await self.db.get_processes(dump_id)
        if len(processes) == 0:
            issues.append("No processes found - dump may not have been processed")

        # Check command log vs database consistency
        commands = await self.db.get_command_history(dump_id, limit=1000)

        # Validate network data
        netscan_cmds = [c for c in commands if 'netscan' in c.get('plugin_name', '').lower()]
        if netscan_cmds:
            netscan_rows = netscan_cmds[0].get('row_count', 0)
            connections = await self.db.get_network_connections(dump_id)
            db_rows = len(connections)

            if netscan_rows > 0 and db_rows == 0:
                issues.append(
                    f"Network data mismatch: Volatility netscan found {netscan_rows} "
                    f"connections but database has 0 - possible parsing error"
                )
            elif netscan_rows != db_rows:
                warnings.append(
                    f"Network data count mismatch: Volatility={netscan_rows}, Database={db_rows}"
                )

        # Validate process data
        pslist_cmds = [c for c in commands if 'pslist' in c.get('plugin_name', '').lower()]
        if pslist_cmds:
            pslist_rows = pslist_cmds[0].get('row_count', 0)
            db_rows = len(processes)

            if pslist_rows != db_rows:
                warnings.append(
                    f"Process count mismatch: Volatility={pslist_rows}, Database={db_rows}"
                )

        # Check for failed commands
        failed_cmds = [c for c in commands if not c.get('success', True)]
        if failed_cmds:
            for cmd in failed_cmds:
                error = cmd.get('error_message', 'Unknown error')
                warnings.append(
                    f"Command '{cmd.get('plugin_name')}' failed: {error}"
                )

        return {
            "valid": len(issues) == 0,
            "issues": issues,
            "warnings": warnings,
            "stats": {
                "total_commands": len(commands),
                "failed_commands": len(failed_cmds),
                "process_count": len(processes),
                "network_count": len(await self.db.get_network_connections(dump_id))
            }
        }

    async def compare_volatility_to_database(
        self,
        dump_id: str,
        volatility_results: Dict[str, int],
        database_results: Dict[str, int]
    ) -> List[str]:
        """
        Compare Volatility command results with database storage

        Args:
            dump_id: Dump identifier
            volatility_results: Dict mapping data type to Volatility row count
            database_results: Dict mapping data type to database row count

        Returns:
            List of warning messages
        """
        warnings = []

        for data_type, vol_count in volatility_results.items():
            db_count = database_results.get(data_type, 0)

            if vol_count > 0 and db_count == 0:
                warnings.append(
                    f"{data_type}: Volatility returned {vol_count} rows but 0 "
                    f"were stored in database - check for parsing errors"
                )
            elif vol_count != db_count:
                diff = vol_count - db_count
                warnings.append(
                    f"{data_type}: Count mismatch (Volatility={vol_count}, "
                    f"Database={db_count}, Difference={diff})"
                )

        return warnings

    def validate_plugin_output(
        self,
        plugin_name: str,
        results: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Validate that plugin output has expected columns

        Args:
            plugin_name: Name of the Volatility plugin
            results: List of result dictionaries

        Returns:
            Dict with 'valid' (bool) and 'missing_columns' (list)
        """
        expected_columns = self._get_expected_columns(plugin_name)

        if not results or not expected_columns:
            return {"valid": True, "missing_columns": []}

        actual_columns = set(results[0].keys())
        expected_set = set(expected_columns)
        missing = expected_set - actual_columns

        return {
            "valid": len(missing) == 0,
            "missing_columns": list(missing),
            "unexpected_columns": list(actual_columns - expected_set)
        }

    def _get_expected_columns(self, plugin_name: str) -> List[str]:
        """Get expected column names for a Volatility plugin"""
        # Map plugin names to expected columns
        column_map = {
            'NetScan': ['Offset', 'Proto', 'LocalAddr', 'LocalPort',
                       'ForeignAddr', 'ForeignPort', 'State', 'PID', 'Owner', 'Created'],
            'PsList': ['PID', 'PPID', 'ImageFileName', 'Offset', 'Threads',
                      'Handles', 'SessionId', 'Wow64', 'CreateTime', 'ExitTime'],
            'CmdLine': ['PID', 'Process', 'Args'],
            'DllList': ['PID', 'Process', 'Base', 'Size', 'Name', 'Path'],
            'Malfind': ['PID', 'Process', 'Start', 'End', 'Tag', 'Protection', 'CommitCharge', 'PrivateMemory', 'Hexdump', 'Disasm'],
        }

        # Extract plugin class name from full module path
        for key in column_map:
            if key.lower() in plugin_name.lower():
                return column_map[key]

        return []
