"""Cleanup utilities for memory dump extractions and temporary files"""
import shutil
import time
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import zipfile

logger = logging.getLogger(__name__)


class ManagedExtraction:
    """Context manager for memory dump extraction with guaranteed cleanup"""

    def __init__(self, dump_path: Path, extraction_dir: Path, dump_id: str,
                 auto_cleanup: bool = True):
        """
        Initialize managed extraction

        Args:
            dump_path: Path to the dump file (possibly .zip)
            extraction_dir: Base directory for extractions
            dump_id: Identifier for this dump
            auto_cleanup: Whether to cleanup on exit
        """
        self.dump_path = dump_path
        self.extraction_dir = extraction_dir
        self.dump_id = dump_id
        self.auto_cleanup = auto_cleanup
        self.extracted_path = None
        self.temp_dir = None

    def __enter__(self) -> Path:
        """Extract the dump and return path to extracted file"""
        timestamp = int(time.time())
        self.temp_dir = self.extraction_dir / f"memdump_{self.dump_id}_{timestamp}"
        self.temp_dir.mkdir(parents=True, exist_ok=True)

        if self.dump_path.suffix.lower() == '.zip':
            logger.info(f"Extracting {self.dump_path.name} to {self.temp_dir}")

            with zipfile.ZipFile(self.dump_path, 'r') as zip_ref:
                zip_ref.extractall(self.temp_dir)

            # Find the actual memory dump file
            for ext in ['.raw', '.mem', '.dmp', '.vmem', '.bin']:
                extracted_files = list(self.temp_dir.rglob(f'*{ext}'))
                if extracted_files:
                    self.extracted_path = extracted_files[0]
                    return self.extracted_path

            # If no specific extension, return first file
            files = list(self.temp_dir.iterdir())
            if files:
                self.extracted_path = files[0]
                return self.extracted_path

            raise ValueError(f"No memory dump found in {self.dump_path}")
        else:
            # Not a zip, return original path
            self.extracted_path = self.dump_path
            return self.extracted_path

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Cleanup extracted files"""
        if self.auto_cleanup and self.temp_dir and self.temp_dir.exists():
            try:
                logger.info(f"Cleaning up extraction: {self.temp_dir}")
                shutil.rmtree(self.temp_dir, ignore_errors=True)
            except Exception as e:
                logger.warning(f"Failed to cleanup {self.temp_dir}: {e}")


def cleanup_old_extractions(extraction_dir: Path,
                           retention_hours: int = 24,
                           dry_run: bool = False) -> Dict[str, Any]:
    """
    Remove extraction directories older than retention period

    Args:
        extraction_dir: Directory containing extractions
        retention_hours: Keep extractions newer than this many hours
        dry_run: If True, don't actually delete, just report

    Returns:
        Dict with cleanup statistics
    """
    if not extraction_dir.exists():
        return {
            'removed_count': 0,
            'freed_bytes': 0,
            'errors': []
        }

    cutoff_time = time.time() - (retention_hours * 3600)
    removed_count = 0
    freed_bytes = 0
    errors = []

    for extraction in extraction_dir.glob("memdump_*"):
        if not extraction.is_dir():
            continue

        try:
            mtime = extraction.stat().st_mtime
            if mtime < cutoff_time:
                # Calculate size before deletion
                size = get_directory_size(extraction)

                if dry_run:
                    logger.info(f"Would remove: {extraction} ({size / (1024**3):.2f} GB)")
                else:
                    logger.info(f"Removing old extraction: {extraction} ({size / (1024**3):.2f} GB)")
                    shutil.rmtree(extraction)

                removed_count += 1
                freed_bytes += size
        except Exception as e:
            error_msg = f"Failed to remove {extraction}: {e}"
            logger.error(error_msg)
            errors.append(error_msg)

    return {
        'removed_count': removed_count,
        'freed_bytes': freed_bytes,
        'freed_gb': freed_bytes / (1024**3),
        'errors': errors,
        'dry_run': dry_run
    }


def cleanup_all_extractions(extraction_dir: Path) -> Dict[str, Any]:
    """
    Remove all extraction directories

    Args:
        extraction_dir: Directory containing extractions

    Returns:
        Dict with cleanup statistics
    """
    if not extraction_dir.exists():
        return {
            'removed_count': 0,
            'freed_bytes': 0,
            'errors': []
        }

    removed_count = 0
    freed_bytes = 0
    errors = []

    for extraction in extraction_dir.glob("memdump_*"):
        if not extraction.is_dir():
            continue

        try:
            size = get_directory_size(extraction)
            logger.info(f"Removing extraction: {extraction} ({size / (1024**3):.2f} GB)")
            shutil.rmtree(extraction)
            removed_count += 1
            freed_bytes += size
        except Exception as e:
            error_msg = f"Failed to remove {extraction}: {e}"
            logger.error(error_msg)
            errors.append(error_msg)

    return {
        'removed_count': removed_count,
        'freed_bytes': freed_bytes,
        'freed_gb': freed_bytes / (1024**3),
        'errors': errors
    }


def get_directory_size(path: Path) -> int:
    """
    Calculate total size of a directory

    Args:
        path: Directory path

    Returns:
        Size in bytes
    """
    total = 0
    try:
        for item in path.rglob('*'):
            if item.is_file():
                total += item.stat().st_size
    except Exception as e:
        logger.warning(f"Error calculating size for {path}: {e}")
    return total


def get_disk_usage(data_dir: Path, extraction_dir: Path) -> Dict[str, Any]:
    """
    Get disk usage statistics for MCP server

    Args:
        data_dir: Main data directory
        extraction_dir: Extractions directory

    Returns:
        Dict with usage statistics
    """
    stats = {
        'data_dir': str(data_dir),
        'extraction_dir': str(extraction_dir),
        'database_size_bytes': 0,
        'database_size_mb': 0,
        'exports_size_bytes': 0,
        'exports_size_mb': 0,
        'extractions_size_bytes': 0,
        'extractions_size_gb': 0,
        'extractions_count': 0,
        'total_size_bytes': 0,
        'total_size_gb': 0
    }

    # Database size
    db_file = data_dir / "artifacts.db"
    if db_file.exists():
        stats['database_size_bytes'] = db_file.stat().st_size
        stats['database_size_mb'] = stats['database_size_bytes'] / (1024**2)

    # Exports size
    exports_dir = data_dir / "exports"
    if exports_dir.exists():
        stats['exports_size_bytes'] = get_directory_size(exports_dir)
        stats['exports_size_mb'] = stats['exports_size_bytes'] / (1024**2)

    # Extractions size
    if extraction_dir.exists():
        stats['extractions_size_bytes'] = get_directory_size(extraction_dir)
        stats['extractions_size_gb'] = stats['extractions_size_bytes'] / (1024**3)
        stats['extractions_count'] = len(list(extraction_dir.glob("memdump_*")))

    # Total
    stats['total_size_bytes'] = (
        stats['database_size_bytes'] +
        stats['exports_size_bytes'] +
        stats['extractions_size_bytes']
    )
    stats['total_size_gb'] = stats['total_size_bytes'] / (1024**3)

    return stats


def list_extractions(extraction_dir: Path) -> List[Dict[str, Any]]:
    """
    List all current extractions with metadata

    Args:
        extraction_dir: Directory containing extractions

    Returns:
        List of extraction info dicts
    """
    if not extraction_dir.exists():
        return []

    extractions = []

    for extraction in extraction_dir.glob("memdump_*"):
        if not extraction.is_dir():
            continue

        try:
            stat = extraction.stat()
            size = get_directory_size(extraction)
            age_hours = (time.time() - stat.st_mtime) / 3600

            extractions.append({
                'path': str(extraction),
                'name': extraction.name,
                'size_bytes': size,
                'size_gb': size / (1024**3),
                'created': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                'age_hours': age_hours
            })
        except Exception as e:
            logger.warning(f"Error reading {extraction}: {e}")

    # Sort by age (newest first)
    extractions.sort(key=lambda x: x['age_hours'])

    return extractions
