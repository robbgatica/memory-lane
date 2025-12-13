"""Database schema and operations for memory forensics artifacts"""
import aiosqlite
from pathlib import Path
from typing import Optional, List, Dict, Any
import json

class ForensicsDatabase:
    """Manages SQLite database for processed memory artifacts"""

    def __init__(self, db_path: Path):
        self.db_path = db_path

    async def initialize(self):
        """Create database schema"""
        async with aiosqlite.connect(self.db_path) as db:
            # Memory dumps metadata
            await db.execute("""
                CREATE TABLE IF NOT EXISTS dumps (
                    dump_id TEXT PRIMARY KEY,
                    file_path TEXT NOT NULL,
                    file_size INTEGER,
                    os_type TEXT,
                    os_version TEXT,
                    last_processed TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    status TEXT DEFAULT 'new'
                )
            """)

            # Processes
            await db.execute("""
                CREATE TABLE IF NOT EXISTS processes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    dump_id TEXT NOT NULL,
                    pid INTEGER NOT NULL,
                    ppid INTEGER,
                    name TEXT,
                    path TEXT,
                    cmdline TEXT,
                    create_time TEXT,
                    exit_time TEXT,
                    is_hidden BOOLEAN DEFAULT 0,
                    is_suspicious BOOLEAN DEFAULT 0,
                    FOREIGN KEY (dump_id) REFERENCES dumps(dump_id),
                    UNIQUE(dump_id, pid)
                )
            """)

            # Memory regions (for injection detection)
            await db.execute("""
                CREATE TABLE IF NOT EXISTS memory_regions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    dump_id TEXT NOT NULL,
                    pid INTEGER NOT NULL,
                    base_address TEXT,
                    size INTEGER,
                    protection TEXT,
                    is_file_backed BOOLEAN,
                    backing_file TEXT,
                    is_suspicious BOOLEAN DEFAULT 0,
                    FOREIGN KEY (dump_id) REFERENCES dumps(dump_id)
                )
            """)

            # Network connections
            await db.execute("""
                CREATE TABLE IF NOT EXISTS network_connections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    dump_id TEXT NOT NULL,
                    pid INTEGER,
                    local_addr TEXT,
                    local_port INTEGER,
                    remote_addr TEXT,
                    remote_port INTEGER,
                    state TEXT,
                    protocol TEXT,
                    FOREIGN KEY (dump_id) REFERENCES dumps(dump_id),
                    UNIQUE(dump_id, pid, local_addr, local_port, remote_addr, remote_port, protocol)
                )
            """)

            # DLLs
            await db.execute("""
                CREATE TABLE IF NOT EXISTS dlls (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    dump_id TEXT NOT NULL,
                    pid INTEGER NOT NULL,
                    base_address TEXT,
                    size INTEGER,
                    name TEXT,
                    path TEXT,
                    FOREIGN KEY (dump_id) REFERENCES dumps(dump_id)
                )
            """)

            # Command execution log
            await db.execute("""
                CREATE TABLE IF NOT EXISTS command_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    dump_id TEXT NOT NULL,
                    plugin_name TEXT NOT NULL,
                    command_line TEXT NOT NULL,
                    parameters TEXT,
                    executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    execution_time_ms INTEGER,
                    row_count INTEGER,
                    success BOOLEAN DEFAULT 1,
                    error_message TEXT,
                    FOREIGN KEY (dump_id) REFERENCES dumps(dump_id)
                )
            """)

            # File hashes for dumps
            await db.execute("""
                CREATE TABLE IF NOT EXISTS dump_hashes (
                    dump_id TEXT PRIMARY KEY,
                    md5 TEXT,
                    sha1 TEXT,
                    sha256 TEXT,
                    calculated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (dump_id) REFERENCES dumps(dump_id)
                )
            """)

            # Extracted files tracking
            await db.execute("""
                CREATE TABLE IF NOT EXISTS extracted_files (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    dump_id TEXT NOT NULL,
                    extraction_type TEXT NOT NULL,
                    source_pid INTEGER,
                    source_address TEXT,
                    output_path TEXT NOT NULL,
                    file_size INTEGER,
                    file_hash_sha256 TEXT,
                    extracted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (dump_id) REFERENCES dumps(dump_id)
                )
            """)

            # Create indexes for performance
            await db.execute("CREATE INDEX IF NOT EXISTS idx_processes_dump_pid ON processes(dump_id, pid)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_processes_name ON processes(name)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_network_dump ON network_connections(dump_id)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_memory_regions_dump_pid ON memory_regions(dump_id, pid)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_command_log_dump ON command_log(dump_id)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_command_log_timestamp ON command_log(executed_at)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_extracted_dump ON extracted_files(dump_id)")

            await db.commit()

    async def add_dump(self, dump_id: str, file_path: str, file_size: int, os_type: str = None):
        """Register a new memory dump"""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                "INSERT OR REPLACE INTO dumps (dump_id, file_path, file_size, os_type) VALUES (?, ?, ?, ?)",
                (dump_id, file_path, file_size, os_type)
            )
            await db.commit()

    async def get_dump(self, dump_id: str) -> Optional[Dict[str, Any]]:
        """Get dump metadata"""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute("SELECT * FROM dumps WHERE dump_id = ?", (dump_id,)) as cursor:
                row = await cursor.fetchone()
                return dict(row) if row else None

    async def list_dumps(self) -> List[Dict[str, Any]]:
        """List all registered dumps"""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute("SELECT * FROM dumps ORDER BY last_processed DESC") as cursor:
                rows = await cursor.fetchall()
                return [dict(row) for row in rows]

    async def add_processes(self, dump_id: str, processes: List[Dict[str, Any]]):
        """Bulk insert processes"""
        async with aiosqlite.connect(self.db_path) as db:
            for proc in processes:
                await db.execute("""
                    INSERT OR REPLACE INTO processes
                    (dump_id, pid, ppid, name, path, cmdline, create_time, is_hidden, is_suspicious)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    dump_id,
                    proc.get('pid'),
                    proc.get('ppid'),
                    proc.get('name'),
                    proc.get('path'),
                    proc.get('cmdline'),
                    proc.get('create_time'),
                    proc.get('is_hidden', False),
                    proc.get('is_suspicious', False)
                ))
            await db.commit()

    async def get_processes(self, dump_id: str, suspicious_only: bool = False) -> List[Dict[str, Any]]:
        """Get processes for a dump"""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            query = "SELECT * FROM processes WHERE dump_id = ?"
            params = [dump_id]

            if suspicious_only:
                query += " AND is_suspicious = 1"

            query += " ORDER BY pid"

            async with db.execute(query, params) as cursor:
                rows = await cursor.fetchall()
                return [dict(row) for row in rows]

    async def get_process_by_pid(self, dump_id: str, pid: int) -> Optional[Dict[str, Any]]:
        """Get specific process details"""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM processes WHERE dump_id = ? AND pid = ?",
                (dump_id, pid)
            ) as cursor:
                row = await cursor.fetchone()
                return dict(row) if row else None

    async def clear_network_connections(self, dump_id: str):
        """Clear network connections for a dump before reprocessing"""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                "DELETE FROM network_connections WHERE dump_id = ?",
                (dump_id,)
            )
            await db.commit()

    async def add_network_connections(self, dump_id: str, connections: List[Dict[str, Any]]):
        """Bulk insert network connections"""
        async with aiosqlite.connect(self.db_path) as db:
            for conn in connections:
                await db.execute("""
                    INSERT OR IGNORE INTO network_connections
                    (dump_id, pid, local_addr, local_port, remote_addr, remote_port, state, protocol)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    dump_id,
                    conn.get('pid'),
                    conn.get('local_addr'),
                    conn.get('local_port'),
                    conn.get('remote_addr'),
                    conn.get('remote_port'),
                    conn.get('state'),
                    conn.get('protocol')
                ))
            await db.commit()

    async def get_network_connections(self, dump_id: str, pid: Optional[int] = None) -> List[Dict[str, Any]]:
        """Get network connections"""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            if pid:
                query = "SELECT * FROM network_connections WHERE dump_id = ? AND pid = ?"
                params = (dump_id, pid)
            else:
                query = "SELECT * FROM network_connections WHERE dump_id = ?"
                params = (dump_id,)

            async with db.execute(query, params) as cursor:
                rows = await cursor.fetchall()
                return [dict(row) for row in rows]

    async def clear_memory_regions(self, dump_id: str):
        """Clear memory regions for a dump before reprocessing"""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                "DELETE FROM memory_regions WHERE dump_id = ?",
                (dump_id,)
            )
            await db.commit()

    async def add_memory_regions(self, dump_id: str, regions: List[Dict[str, Any]]):
        """Bulk insert memory regions"""
        async with aiosqlite.connect(self.db_path) as db:
            for region in regions:
                await db.execute("""
                    INSERT INTO memory_regions
                    (dump_id, pid, base_address, size, protection, is_file_backed, backing_file, is_suspicious)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    dump_id,
                    region.get('pid'),
                    region.get('base_address'),
                    region.get('size'),
                    region.get('protection'),
                    region.get('is_file_backed', False),
                    region.get('backing_file'),
                    region.get('is_suspicious', False)
                ))
            await db.commit()

    async def get_suspicious_memory_regions(self, dump_id: str, pid: Optional[int] = None) -> List[Dict[str, Any]]:
        """Get suspicious memory regions (potential injection)"""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            query = "SELECT * FROM memory_regions WHERE dump_id = ? AND is_suspicious = 1"
            params = [dump_id]

            if pid:
                query += " AND pid = ?"
                params.append(pid)

            async with db.execute(query, params) as cursor:
                rows = await cursor.fetchall()
                return [dict(row) for row in rows]

    async def add_command_log(self, dump_id: str, plugin_name: str, command_line: str,
                             parameters: str = None, execution_time_ms: int = 0,
                             row_count: int = 0, success: bool = True, error_message: str = None):
        """Log a Volatility command execution"""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                INSERT INTO command_log
                (dump_id, plugin_name, command_line, parameters, execution_time_ms, row_count, success, error_message)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (dump_id, plugin_name, command_line, parameters, execution_time_ms, row_count, success, error_message))
            await db.commit()

    async def get_command_history(self, dump_id: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Get command execution history for a dump"""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute("""
                SELECT * FROM command_log
                WHERE dump_id = ?
                ORDER BY executed_at DESC
                LIMIT ?
            """, (dump_id, limit)) as cursor:
                rows = await cursor.fetchall()
                return [dict(row) for row in rows]

    async def get_command_stats(self, dump_id: str) -> Dict[str, Any]:
        """Get command execution statistics for a dump"""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute("""
                SELECT
                    COUNT(*) as total_commands,
                    SUM(row_count) as total_rows,
                    AVG(execution_time_ms) as avg_execution_time,
                    SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END) as failed_commands
                FROM command_log
                WHERE dump_id = ?
            """, (dump_id,)) as cursor:
                row = await cursor.fetchone()
                return dict(row) if row else {}

    async def store_dump_hashes(self, dump_id: str, hashes: Dict[str, str]):
        """Store file hashes for a dump"""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                INSERT OR REPLACE INTO dump_hashes (dump_id, md5, sha1, sha256)
                VALUES (?, ?, ?, ?)
            """, (dump_id, hashes.get('md5'), hashes.get('sha1'), hashes.get('sha256')))
            await db.commit()

    async def get_dump_hashes(self, dump_id: str) -> Optional[Dict[str, str]]:
        """Get cached file hashes for a dump"""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute("""
                SELECT md5, sha1, sha256, calculated_at
                FROM dump_hashes
                WHERE dump_id = ?
            """, (dump_id,)) as cursor:
                row = await cursor.fetchone()
                return dict(row) if row else None

    async def add_extracted_file(self, dump_id: str, extraction_type: str,
                                output_path: str, file_size: int,
                                file_hash_sha256: str, source_pid: int = None,
                                source_address: str = None):
        """Track an extracted file"""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                INSERT INTO extracted_files
                (dump_id, extraction_type, source_pid, source_address, output_path, file_size, file_hash_sha256)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (dump_id, extraction_type, source_pid, source_address, output_path, file_size, file_hash_sha256))
            await db.commit()

    async def get_extracted_files(self, dump_id: str) -> List[Dict[str, Any]]:
        """Get all extracted files for a dump"""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute("""
                SELECT * FROM extracted_files
                WHERE dump_id = ?
                ORDER BY extracted_at DESC
            """, (dump_id,)) as cursor:
                rows = await cursor.fetchall()
                return [dict(row) for row in rows]

    async def mark_process_suspicious(self, dump_id: str, pid: int, is_suspicious: bool = True):
        """Mark a specific process as suspicious or not"""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                UPDATE processes
                SET is_suspicious = ?
                WHERE dump_id = ? AND pid = ?
            """, (is_suspicious, dump_id, pid))
            await db.commit()

    async def mark_processes_suspicious(self, dump_id: str, pids: List[int]):
        """Bulk mark multiple processes as suspicious"""
        async with aiosqlite.connect(self.db_path) as db:
            for pid in pids:
                await db.execute("""
                    UPDATE processes
                    SET is_suspicious = 1
                    WHERE dump_id = ? AND pid = ?
                """, (dump_id, pid))
            await db.commit()
