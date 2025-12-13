"""Export forensic artifacts in multiple formats"""
import json
import csv
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime
from database import ForensicsDatabase
from validation import DataValidator


class DataExporter:
    """Export forensic data in various formats"""

    def __init__(self, db: ForensicsDatabase):
        self.db = db

    async def export_json(self, dump_id: str, output_path: Path,
                         data_types: List[str] = None,
                         include_provenance: bool = True) -> Dict[str, Any]:
        """
        Export data to JSON format

        Args:
            dump_id: Dump identifier
            output_path: Output file path
            data_types: List of data types to export (['processes', 'network', 'memory_regions', 'all'])
            include_provenance: Include command history

        Returns:
            Export statistics
        """
        if data_types is None or 'all' in data_types:
            data_types = ['processes', 'network', 'memory_regions']

        # Gather data
        export_data = {
            'dump_id': dump_id,
            'export_timestamp': datetime.now().isoformat(),
            'data': {}
        }

        total_records = 0

        if 'processes' in data_types:
            processes = await self.db.get_processes(dump_id)
            export_data['data']['processes'] = processes
            total_records += len(processes)

        if 'network' in data_types:
            connections = await self.db.get_network_connections(dump_id)
            export_data['data']['network_connections'] = connections
            total_records += len(connections)

        if 'memory_regions' in data_types:
            regions = await self.db.get_suspicious_memory_regions(dump_id)
            export_data['data']['memory_regions'] = regions
            total_records += len(regions)

        # Add provenance
        if include_provenance:
            commands = await self.db.get_command_history(dump_id, limit=1000)
            stats = await self.db.get_command_stats(dump_id)
            export_data['provenance'] = {
                'commands': commands,
                'statistics': stats
            }

        # Write JSON
        with open(output_path, 'w') as f:
            json.dump(export_data, f, indent=2, default=str)

        return {
            'format': 'JSON',
            'output_path': str(output_path),
            'file_size': output_path.stat().st_size,
            'total_records': total_records,
            'data_types': data_types
        }

    async def export_csv(self, dump_id: str, data_type: str,
                        output_path: Path) -> Dict[str, Any]:
        """
        Export specific data type to CSV

        Args:
            dump_id: Dump identifier
            data_type: One of 'processes', 'network', 'memory_regions'
            output_path: Output file path

        Returns:
            Export statistics
        """
        # Get data
        data = await self._get_data_by_type(dump_id, data_type)

        if not data:
            raise ValueError(f"No data found for type '{data_type}'")

        # Write CSV
        with open(output_path, 'w', newline='') as f:
            if data:
                writer = csv.DictWriter(f, fieldnames=data[0].keys())
                writer.writeheader()
                writer.writerows(data)

        return {
            'format': 'CSV',
            'output_path': str(output_path),
            'file_size': output_path.stat().st_size,
            'total_records': len(data),
            'data_type': data_type
        }

    async def export_html(self, dump_id: str, output_path: Path,
                         template_name: str = 'report_template.html') -> Dict[str, Any]:
        """
        Export to HTML format using templates

        Args:
            dump_id: Dump identifier
            output_path: Output file path
            template_name: Template file name

        Returns:
            Export statistics
        """
        try:
            from jinja2 import Environment, FileSystemLoader, select_autoescape
        except ImportError:
            raise ImportError("jinja2 is required for HTML export. Install it with: pip install jinja2")

        from config import TEMPLATES_DIR

        # Gather all data
        data = await self._gather_all_data(dump_id)

        # Load Jinja2 template
        env = Environment(
            loader=FileSystemLoader(TEMPLATES_DIR),
            autoescape=select_autoescape(['html'])
        )

        try:
            template = env.get_template(template_name)
        except Exception:
            # If template doesn't exist, create basic HTML
            return await self._export_basic_html(dump_id, output_path, data)

        # Render template
        html = template.render(**data)

        # Write HTML
        with open(output_path, 'w') as f:
            f.write(html)

        return {
            'format': 'HTML',
            'output_path': str(output_path),
            'file_size': output_path.stat().st_size
        }

    async def _get_data_by_type(self, dump_id: str, data_type: str) -> List[Dict[str, Any]]:
        """Get data for specific type"""
        if data_type == 'processes':
            return await self.db.get_processes(dump_id)
        elif data_type == 'network':
            return await self.db.get_network_connections(dump_id)
        elif data_type == 'memory_regions':
            return await self.db.get_suspicious_memory_regions(dump_id)
        else:
            raise ValueError(f"Unknown data type: {data_type}")

    async def _gather_all_data(self, dump_id: str) -> Dict[str, Any]:
        """Gather all data for comprehensive export"""
        # Get dump metadata
        dump = await self.db.get_dump(dump_id)

        # Get hashes
        hashes = await self.db.get_dump_hashes(dump_id)

        # Get processes
        processes = await self.db.get_processes(dump_id)
        suspicious_processes = [p for p in processes if p.get('is_suspicious')]

        # Get network connections
        connections = await self.db.get_network_connections(dump_id)

        # Get memory regions
        regions = await self.db.get_suspicious_memory_regions(dump_id)

        # Get command history
        commands = await self.db.get_command_history(dump_id, limit=100)
        command_lines = [cmd['command_line'] for cmd in commands]

        # Get statistics
        stats = await self.db.get_command_stats(dump_id)

        # Validate data integrity
        validator = DataValidator(self.db)
        validation_result = await validator.validate_dump_integrity(dump_id)

        return {
            'dump_id': dump_id,
            'dump': dump,
            'hashes': hashes,
            'generated_at': datetime.now().isoformat(),
            'processes': processes,
            'process_count': len(processes),
            'suspicious_process_count': len(suspicious_processes),
            'connections': connections,
            'connection_count': len(connections),
            'memory_regions': regions,
            'region_count': len(regions),
            'commands': command_lines,
            'command_stats': stats,
            'validation': validation_result
        }

    async def _export_basic_html(self, dump_id: str, output_path: Path,
                                 data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate basic HTML when template not available"""
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Memory Forensics Report - {dump_id}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
        .section {{ background: white; margin: 20px 0; padding: 20px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        h2 {{ color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }}
        table {{ border-collapse: collapse; width: 100%; margin: 10px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
        th {{ background-color: #34495e; color: white; }}
        .suspicious {{ background-color: #e74c3c; color: white; }}
        .metadata {{ background: #ecf0f1; padding: 15px; border-radius: 5px; }}
        .command {{ background: #2c3e50; color: #2ecc71; padding: 10px; font-family: monospace; margin: 5px 0; border-radius: 3px; }}
        .stats {{ display: flex; justify-content: space-around; }}
        .stat-box {{ text-align: center; padding: 15px; background: #3498db; color: white; border-radius: 5px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Memory Forensics Analysis Report</h1>
        <h2>{dump_id}</h2>
        <p>Generated: {data['generated_at']}</p>
    </div>

    <div class="section">
        <h2>Summary Statistics</h2>
        <div class="stats">
            <div class="stat-box">
                <h3>{data['process_count']}</h3>
                <p>Total Processes</p>
            </div>
            <div class="stat-box">
                <h3>{data['suspicious_process_count']}</h3>
                <p>Suspicious Processes</p>
            </div>
            <div class="stat-box">
                <h3>{data['connection_count']}</h3>
                <p>Network Connections</p>
            </div>
            <div class="stat-box">
                <h3>{data['region_count']}</h3>
                <p>Suspicious Memory Regions</p>
            </div>
        </div>
    </div>

    <div class="section">
        <h2>Dump Metadata</h2>
        <div class="metadata">
            <p><strong>File:</strong> {data['dump'].get('file_path', 'N/A')}</p>
            <p><strong>Size:</strong> {data['dump'].get('file_size', 0) / (1024*1024):.2f} MB</p>
"""

        # Add hashes if available
        if data.get('hashes'):
            html += f"""
            <p><strong>MD5:</strong> {data['hashes'].get('md5', 'N/A')}</p>
            <p><strong>SHA1:</strong> {data['hashes'].get('sha1', 'N/A')}</p>
            <p><strong>SHA256:</strong> {data['hashes'].get('sha256', 'N/A')}</p>
"""

        html += """
        </div>
    </div>
"""

        # Add data quality warnings if present
        validation = data.get('validation', {})
        if not validation.get('valid', True) or validation.get('warnings'):
            html += """
    <div class="section" style="background: #fff3cd; border-left: 4px solid #ffc107;">
        <h2>Data Quality Warnings</h2>
"""
            if validation.get('issues'):
                html += "        <h3>Critical Issues:</h3>\n        <ul>\n"
                for issue in validation['issues']:
                    html += f"            <li><strong>ERROR:</strong> {issue}</li>\n"
                html += "        </ul>\n"

            if validation.get('warnings'):
                html += "        <h3>Warnings:</h3>\n        <ul>\n"
                for warning in validation['warnings']:
                    html += f"            <li><strong>WARNING:</strong> {warning}</li>\n"
                html += "        </ul>\n"

            html += """    </div>
"""

        html += """
    <div class="section">
        <h2>Command Provenance</h2>
"""

        # Add commands
        for cmd in data.get('commands', [])[:20]:  # Limit to 20
            html += f'        <div class="command">{cmd}</div>\n'

        html += """
    </div>

    <div class="section">
        <h2>Processes</h2>
        <table>
            <tr>
                <th>PID</th>
                <th>PPID</th>
                <th>Name</th>
                <th>Created</th>
                <th>Flags</th>
            </tr>
"""

        # Add process rows
        for proc in data.get('processes', [])[:100]:  # Limit to 100
            flags = []
            if proc.get('is_hidden'):
                flags.append('HIDDEN')
            if proc.get('is_suspicious'):
                flags.append('SUSPICIOUS')
            flag_str = ', '.join(flags) if flags else '-'

            row_class = 'suspicious' if proc.get('is_suspicious') else ''
            html += f"""
            <tr class="{row_class}">
                <td>{proc.get('pid', 'N/A')}</td>
                <td>{proc.get('ppid', 'N/A')}</td>
                <td>{proc.get('name', 'N/A')}</td>
                <td>{str(proc.get('create_time', 'N/A'))[:19]}</td>
                <td>{flag_str}</td>
            </tr>
"""

        html += """
        </table>
    </div>
</body>
</html>
"""

        # Write HTML
        with open(output_path, 'w') as f:
            f.write(html)

        return {
            'format': 'HTML',
            'output_path': str(output_path),
            'file_size': output_path.stat().st_size
        }
