# Troubleshooting Guide

This guide helps diagnose and fix common issues with the Memory Forensics MCP Server.

## Quick Diagnostics

### Check Data Integrity

Run the health check tool after processing a dump:

```
health_check for <dump_id>
```

This will identify common issues like:
- Missing data that should be present
- Mismatches between Volatility results and database
- Failed commands

---

## Common Issues

### 1. Network Connections Show as 0

**Symptoms:**
- `process_dump` reports finding network connections (e.g., "Found 73 connections")
- Database shows 0 connections stored
- `network_analysis` shows "No network connections found"
- HTML export shows 0 connections

**Root Cause:**
Missing Python dependency (`pefile`) causes silent import failure. When `windows.netscan` plugin tries to import `pefile`, it fails and returns empty results without raising an error.

**Fix:**
Install the missing dependency:
```bash
pip install pefile
# Or if using system Python:
pip install --break-system-packages pefile
```

**Verification:**
```bash
# Test if pefile is installed
python3 -c "import pefile; print('pefile installed successfully')"

# Check if the fix is applied in volatility_handler.py
grep -A 2 "except ImportError as e:" volatility_handler.py
# Should show critical logging for missing dependencies
```

**Prevention:**
This is now fixed in `volatility_handler.py`:
- UnreadableValue objects are properly handled (converted to None)
- ImportError is no longer silently caught - it raises a clear error message
- `pefile` is added to requirements.txt

**Workaround (if you encounter this):**
After installing dependencies, reprocess the dump or manually insert network connections using the fixed code.
```
process_dump for <dump_id>
```

---

### 2. Suspicious Processes Not Flagged

**Symptoms:**
- `detect_anomalies` reports suspicious processes
- HTML export shows 0 suspicious processes
- `list_processes suspicious_only:true` returns empty

**Cause:**
Anomaly detection results weren't being persisted to database.

**Fix:**
This was fixed in `database.py` (added persistence methods) and `server.py` (updated detect_anomalies handler).

**Verification:**
```bash
# Check if fix is applied
grep "mark_processes_suspicious" server.py
# Should show the function being called in detect_anomalies handler
```

**Workaround:**
Run detect_anomalies again after updating:
```
detect_anomalies for <dump_id>
```

---

### 3. Process Dump Returns Error

**Symptoms:**
- `process_dump` fails with "Dump not found"
- Dump is visible in filesystem

**Diagnosis:**
```bash
# Check dumps directory
ls -lh ~/tools/memdumps/

# Check if dump is registered
sqlite3 ~/tools/memory-forensics-mcp/data/artifacts.db "SELECT dump_id, file_path FROM dumps;"
```

**Causes & Fixes:**

**A. Dump not in expected directory:**
```bash
# Move dump to correct location
mv /path/to/dump.zip ~/tools/memdumps/
```

**B. Dump ID doesn't match filename:**
The dump ID is derived from the filename (without extension).
```
File: mini_memory_ctf.zip
Dump ID: mini_memory_ctf
```

**C. Permissions issue:**
```bash
# Fix permissions
chmod 644 ~/tools/memdumps/*.zip
```

---

### 4. Volatility Plugin Fails

**Symptoms:**
- Specific Volatility plugin returns no data
- Error in logs: "Error in get_XXX"

**Diagnosis:**
Check command history for errors:
```bash
sqlite3 ~/tools/memory-forensics-mcp/data/artifacts.db \
  "SELECT plugin_name, success, error_message FROM command_log WHERE success = 0;"
```

**Common Causes:**

**A. Symbol files missing:**
```bash
# Download Windows symbols
cd ~/tools/volatility3
python3 vol.py -f /path/to/dump.mem windows.info
# This will download required symbols
```

**B. Incompatible memory dump:**
Some dumps require specific Volatility versions or ISF files.

```bash
# Check dump compatibility
cd ~/tools/volatility3
python3 vol.py -f /path/to/dump.mem windows.info
```

**C. Corrupted memory dump:**
```bash
# Verify dump integrity
md5sum /path/to/dump.zip
# Compare with known good hash
```

---

### 5. Database Locked Error

**Symptoms:**
- Error: "database is locked"
- Operations fail intermittently

**Cause:**
Multiple connections trying to write simultaneously.

**Fix:**
```bash
# Close any other connections to the database
pkill -f "memory-forensics"

# Restart MCP server
# (Restart Claude Code to reload)
```

**Prevention:**
The server uses connection pooling, but if you're accessing the database externally:
```bash
# Use WAL mode for better concurrency
sqlite3 ~/tools/memory-forensics-mcp/data/artifacts.db "PRAGMA journal_mode=WAL;"
```

---

### 6. Temp Space Full

**Symptoms:**
- Error: "Disk quota exceeded"
- Processing fails during extraction

**Diagnosis:**
```bash
# Check temp space
df -h /tmp
quota -s
```

**Fix:**
```bash
# Clean up old extractions
rm -rf /tmp/memdump_*
rm -rf /tmp/clamav_scan_*

# Or with sudo if permission denied
sudo rm -rf /tmp/memdump_* /tmp/clamav_scan_*
```

**Prevention:**
The server should clean up temp files automatically, but crashes can leave them behind.

---

### 7. Missing Python Dependencies

**Symptoms:**
- ImportError or ModuleNotFoundError
- Server fails to start

**Fix:**
```bash
cd ~/tools/memory-forensics-mcp
source venv/bin/activate
pip install -r requirements.txt
```

**Common missing modules:**
- `pefile` - Required for Volatility Windows plugins
- `jinja2` - Required for HTML exports
- `aiosqlite` - Required for async database operations

---

### 8. HTML Export Incomplete

**Symptoms:**
- HTML report missing sections
- Data appears truncated

**Diagnosis:**
Check if data exists in database:
```bash
sqlite3 ~/tools/memory-forensics-mcp/data/artifacts.db <<EOF
SELECT
  (SELECT COUNT(*) FROM processes WHERE dump_id='mini_memory_ctf') as processes,
  (SELECT COUNT(*) FROM network_connections WHERE dump_id='mini_memory_ctf') as network,
  (SELECT COUNT(*) FROM memory_regions WHERE dump_id='mini_memory_ctf') as regions;
EOF
```

**Fix:**
If data is missing, reprocess the dump:
```
process_dump for <dump_id>
```

---

## Debugging Tips

### Enable Verbose Logging

Edit `volatility_handler.py`:
```python
# Change logging level
logging.basicConfig(level=logging.DEBUG)  # Was: logging.WARNING
```

Restart Claude Code to apply changes.

### Check Raw Volatility Output

Test Volatility directly:
```bash
cd ~/tools/volatility3
python3 vol.py -f ~/tools/memdumps/dump.zip windows.pslist
python3 vol.py -f ~/tools/memdumps/dump.zip windows.netscan
```

### Inspect Database

```bash
# Open database
sqlite3 ~/tools/memory-forensics-mcp/data/artifacts.db

# List tables
.tables

# Check process count
SELECT COUNT(*) FROM processes WHERE dump_id='mini_memory_ctf';

# Check network connections
SELECT * FROM network_connections WHERE dump_id='mini_memory_ctf' LIMIT 5;

# Check command history
SELECT plugin_name, success, row_count, error_message
FROM command_log
WHERE dump_id='mini_memory_ctf'
ORDER BY executed_at DESC;

# Exit
.quit
```

### Validate Plugin Output

Create a test script:
```python
import sys
sys.path.insert(0, "/home/robb/tools/volatility3")

from volatility3.plugins.windows import netscan

# Get expected columns
plugin = netscan.NetScan
# Check what columns it returns
print("Expected columns: Offset, Proto, LocalAddr, LocalPort, ForeignAddr, ForeignPort, State, PID, Owner, Created")
```

---

## Data Validation

### Run Health Check

```
health_check for <dump_id>
```

This checks:
- Data consistency between Volatility and database
- Failed commands
- Missing expected data

### Manual Validation

Compare Volatility output with database:
```bash
# Count processes from Volatility
cd ~/tools/volatility3
python3 vol.py -f ~/tools/memdumps/dump.zip windows.pslist | wc -l

# Count processes in database
sqlite3 ~/tools/memory-forensics-mcp/data/artifacts.db \
  "SELECT COUNT(*) FROM processes WHERE dump_id='<dump_id>';"
```

---

## Performance Issues

### Slow Processing

**Causes:**
- Large memory dumps (>4GB)
- Complex Volatility plugins
- Limited system resources

**Solutions:**

1. **Increase timeout** (if needed):
   Edit `config.py` to add timeout settings

2. **Process in stages**:
   ```
   # Process core data first
   process_dump for <dump_id>

   # Then run additional analysis
   detect_anomalies for <dump_id>
   network_analysis for <dump_id>
   ```

3. **Use SSD for temp files**:
   Ensure /tmp is on SSD, not HDD

---

## Getting Help

### Collect Diagnostic Info

When reporting issues, include:

1. **System info:**
   ```bash
   uname -a
   python3 --version
   df -h
   quota -s
   ```

2. **MCP Server version:**
   ```bash
   cd ~/tools/memory-forensics-mcp
   git log -1 --oneline
   ```

3. **Error logs:**
   Check Claude Code logs for detailed error messages

4. **Database state:**
   ```bash
   sqlite3 ~/tools/memory-forensics-mcp/data/artifacts.db \
     "SELECT dump_id, status FROM dumps;"
   ```

5. **Health check output:**
   ```
   health_check for <dump_id>
   ```

### Report Issues

Include the diagnostic info above and:
- Steps to reproduce
- Expected vs actual behavior
- Relevant log excerpts

---

## Reference

- [README.md](README.md) - Setup and usage
- [VOLATILITY_PLUGINS.md](VOLATILITY_PLUGINS.md) - Plugin column reference
- [Volatility 3 Documentation](https://volatility3.readthedocs.io/)
