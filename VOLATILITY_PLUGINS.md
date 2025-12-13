# Volatility 3 Plugins Reference

This document provides a reference for the Volatility 3 plugins used by the Memory Forensics MCP Server, including expected column names and data types.

## Plugin Column Mappings

### windows.netscan.NetScan

Scans for network objects present in Windows memory.

**Expected Columns:**
- `Offset` (Hex) - Memory offset
- `Proto` (str) - Protocol (TCP/UDP) **NOTE: Not 'Protocol'**
- `LocalAddr` (str) - Local IP address
- `LocalPort` (int) - Local port number
- `ForeignAddr` (str) - Remote IP address
- `ForeignPort` (int) - Remote port number
- `State` (str) - Connection state (LISTENING, ESTABLISHED, etc.)
- `PID` (int) - Process ID
- `Owner` (str) - Process name
- `Created` (datetime) - Connection creation time

**Common Pitfall:**
The column is named `Proto`, not `Protocol`. Using the wrong name will cause parsing failures.

---

### windows.pslist.PsList

Lists active processes by walking the process list.

**Expected Columns:**
- `PID` (int) - Process ID
- `PPID` (int) - Parent Process ID
- `ImageFileName` (str) - Process name
- `Offset` (Hex) - Memory offset
- `Threads` (int) - Number of threads
- `Handles` (int) - Number of handles
- `SessionId` (int) - Session ID
- `Wow64` (bool) - Is 32-bit process on 64-bit system
- `CreateTime` (datetime) - Process creation time
- `ExitTime` (datetime) - Process exit time (if exited)

**Notes:**
- `ImageFileName` is the process name, not a full path
- Hidden processes won't appear in this list (use psscan)

---

### windows.psscan.PsScan

Scans physical memory for EPROCESS structures (finds hidden processes).

**Expected Columns:**
- `PID` (int) - Process ID
- `PPID` (int) - Parent Process ID
- `ImageFileName` (str) - Process name
- `Offset` (Hex) - Physical memory offset
- `Threads` (int) - Number of threads
- `Handles` (int) - Number of handles
- `SessionId` (int) - Session ID
- `Wow64` (bool) - Is 32-bit process on 64-bit system
- `CreateTime` (datetime) - Process creation time
- `ExitTime` (datetime) - Process exit time

**Usage:**
Compare with pslist to detect hidden processes (rootkits).

---

### windows.cmdline.CmdLine

Extracts process command-line arguments.

**Expected Columns:**
- `PID` (int) - Process ID
- `Process` (str) - Process name
- `Args` (str) - Full command line with arguments

**Notes:**
- May return `-` or empty for some system processes
- Command line can reveal malicious scripts or parameters

---

### windows.dlllist.DllList

Lists loaded DLLs for each process.

**Expected Columns:**
- `PID` (int) - Process ID
- `Process` (str) - Process name
- `Base` (Hex) - Base address of DLL
- `Size` (Hex) - Size of DLL in memory
- `Name` (str) - DLL filename
- `Path` (str) - Full path to DLL

**Notes:**
- Can detect DLL injection and unusual DLL loading
- Legitimate DLLs should be in System32/SysWOW64

---

### windows.malfind.Malfind

Detects code injection by finding unbacked executable memory.

**Expected Columns:**
- `PID` (int) - Process ID
- `Process` (str) - Process name
- `Start` (Hex) - Start address of suspicious region
- `End` (Hex) - End address of suspicious region
- `Tag` (str) - Pool tag
- `Protection` (str) - Memory protection (PAGE_EXECUTE_READWRITE is suspicious)
- `CommitCharge` (int) - Committed memory size
- `PrivateMemory` (int) - Private memory size
- `Hexdump` (str) - Hexadecimal dump of memory
- `Disasm` (str) - Disassembly of code

**Red Flags:**
- `PAGE_EXECUTE_READWRITE` protection
- Unbacked memory (not backed by a file on disk)
- Shellcode patterns in disassembly

---

### windows.pstree.PsTree

Shows process hierarchy (parent-child relationships).

**Expected Columns:**
- `PID` (int) - Process ID
- `PPID` (int) - Parent Process ID
- `ImageFileName` (str) - Process name
- `CreateTime` (datetime) - Process creation time

**Usage:**
Visualize process relationships to identify malicious process chains.

---

## Common Issues

### 1. Column Name Mismatches

**Problem:** Code expects different column names than Volatility returns.

**Example:**
```python
# WRONG - will fail
protocol = conn.get('Protocol')  # Volatility returns 'Proto'

# CORRECT
protocol = conn.get('Proto')
```

**Solution:** Always refer to this document for correct column names.

---

### 2. Type Conversions

**Problem:** Some values need to be converted to strings.

**Example:**
```python
# Volatility returns complex objects for addresses
base_address = dll.get('Base')  # May be an Address object

# Convert to string
base_address = hex(dll.get('Base', 0))  # or str()
```

---

### 3. None/Empty Values

**Problem:** Not all processes have all data.

**Example:**
```python
# Some processes don't have command lines
cmdline = proc.get('Args')  # May be '-' or None

# Always provide defaults
cmdline = proc.get('Args', '-')
```

---

## Testing Plugin Parsers

To test that your parser handles Volatility output correctly:

```python
# Mock Volatility output with actual column names
mock_netscan = {
    'Offset': 0xffff8a0123456789,
    'Proto': 'TCP',  # Not 'Protocol'!
    'LocalAddr': '192.168.1.100',
    'LocalPort': 49152,
    'ForeignAddr': '93.184.216.34',
    'ForeignPort': 443,
    'State': 'ESTABLISHED',
    'PID': 1234,
    'Owner': 'chrome.exe',
    'Created': '2024-01-01 12:00:00'
}

# Parse and validate
result = parse_network_connection(mock_netscan)
assert result['protocol'] == 'TCP'  # Should work if column name is correct
```

---

## Plugin Version Compatibility

This documentation is based on **Volatility 3.2.0+**. Column names may vary in older versions.

**Checking Your Version:**
```bash
cd ~/tools/volatility3
python3 vol.py --version
```

**Updating Volatility:**
```bash
cd ~/tools/volatility3
git pull origin develop
pip3 install -r requirements.txt
```

---

## Adding Support for New Plugins

When adding a new Volatility plugin:

1. **Document expected columns** - Add to this file
2. **Update validation.py** - Add to `_get_expected_columns()`
3. **Test column names** - Verify with mock data
4. **Handle type conversions** - Convert addresses, datetimes, etc.
5. **Provide defaults** - Use `.get(column, default_value)`

---

## Reference Links

- [Volatility 3 Documentation](https://volatility3.readthedocs.io/)
- [Volatility 3 GitHub](https://github.com/volatilityfoundation/volatility3)
- [Plugin Development Guide](https://volatility3.readthedocs.io/en/latest/development.html)
