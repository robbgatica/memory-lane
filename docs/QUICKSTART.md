# Quick Start Guide

Complete setup guide from zero to your first memory forensics investigation.

## Prerequisites

- **Python 3.8+**: Check with `python3 --version`
- **Claude Code**: Install from [https://claude.com/claude-code](https://claude.com/claude-code)
- **Volatility 3**: Memory forensics framework
- **Memory dumps**: Windows memory dumps (.raw, .mem, .dmp, .vmem, or .zip)

## Step 1: Set Up Memory Forensics MCP Server

```bash
# Clone or download the repository
git clone <repository-url> memory-forensics-mcp
cd memory-forensics-mcp

# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Install all dependencies (including Volatility 3)
pip install -r requirements.txt
```

## Step 2: Prepare Memory Dumps

```bash
# Memory dumps will go in the 'dumps' directory (auto-created in project)
# Supported formats: .zip, .raw, .mem, .dmp, .vmem

# Copy your dumps to the dumps directory
cp /path/to/your/dump.zip dumps/

# Or configure a custom location by editing config.py:
# DUMPS_DIR = Path("/path/to/your/dumps")
# Or via environment variable:
# export DUMPS_DIR=/path/to/your/dumps
```

## Step 3: Configure Claude Code

Add the MCP server to your Claude Code configuration:

```bash
# Edit the MCP configuration
nano ~/.claude/mcp.json
```

Add this content (replace paths with your actual installation location):

```json
{
  "mcpServers": {
    "memory-forensics": {
      "command": "/absolute/path/to/memory-forensics-mcp/venv/bin/python",
      "args": ["/absolute/path/to/memory-forensics-mcp/server.py"]
    }
  }
}
```

Example:
```json
{
  "mcpServers": {
    "memory-forensics": {
      "command": "/home/username/projects/memory-forensics-mcp/venv/bin/python",
      "args": ["/home/username/projects/memory-forensics-mcp/server.py"]
    }
  }
}
```

**Important**: Replace `/home/robb` with your actual home directory path if different.

## Step 4: Test the Installation

```bash
# Test that dependencies are installed correctly
cd memory-forensics-mcp
source venv/bin/activate
python -c "import mcp, aiosqlite, volatility3; print('[OK] All dependencies installed')"
```

**What to expect:**
- If successful, you'll see: `[OK] All dependencies installed`
- If you see import errors, reinstall dependencies: `pip install -r requirements.txt`

**Note**: You don't need to run `python server.py` manually. Claude Code will start the MCP server automatically when you launch a session. The server communicates via stdio (stdin/stdout) and won't display any output when run directly.

## Step 5: Start Claude Code

```bash
# Start a fresh Claude Code session
claude
```

## Step 6: Verify It Works

In the Claude Code session, ask:

```
"What memory forensics tools do you have available?"
```

You should see Claude list tools like:
- `list_dumps` - List available memory dumps
- `process_dump` - Process a dump with Volatility 3
- `analyze_process` - Deep dive into specific process
- `detect_code_injection` - Find injected code
- `network_analysis` - Analyze network connections
- `detect_hidden_processes` - Find rootkit-hidden processes
- `get_process_tree` - Show parent-child relationships

**If tools are not listed**: The MCP server may not be connected. Check:
1. MCP configuration path is correct in `~/.claude/mcp.json`
2. Virtual environment path is correct
3. Restart Claude Code

## Step 7: Your First Investigation

List available memory dumps:
```
"List available memory dumps"
```

Process a dump (start with the smallest one):
```
"Process the mini_memory_ctf dump and tell me what you find"
```

**Note**: First-time processing takes 5-15 minutes depending on dump size. Results are cached for instant subsequent queries.

## Step 8: Start Investigating!

Try investigative questions:
- "Are there any suspicious processes?"
- "Show me evidence of code injection"
- "What network connections exist?"
- "Analyze process 1234 in detail"
- "Find hidden processes"
- "Show me the process tree"

## Architecture Overview

```
Your Memory Dumps (project/dumps/ or custom location)
       ↓
Volatility 3 (extracts artifacts)
       ↓
SQLite Cache (project/data/artifacts.db)
       ↓
MCP Server (exposes tools)
       ↓
Claude Code (AI-powered analysis)
```

## File Locations

- **MCP Server**: `<install-dir>/memory-forensics-mcp/`
- **Volatility 3**: Installed via pip in venv
- **Your Dumps**: `<install-dir>/memory-forensics-mcp/dumps/` (default)
- **Cached Data**: `<install-dir>/memory-forensics-mcp/data/artifacts.db`
- **MCP Config**: `~/.claude/mcp.json`

## Troubleshooting

### "No tools found" or MCP server not available

1. Verify MCP configuration exists and has correct paths:
   ```bash
   cat ~/.claude/mcp.json
   ```

2. Test dependencies are installed:
   ```bash
   cd memory-forensics-mcp
   source venv/bin/activate
   python -c "import mcp, aiosqlite, volatility3; print('All imports OK')"
   ```

3. Check paths in `config.py` match your setup:
   ```bash
   cat config.py
   # Verify DUMPS_DIR is set correctly
   ```

4. Verify the virtual environment Python path is correct in `~/.claude/mcp.json`

5. Restart Claude Code completely (exit and start new session)

### "Volatility import error"

```bash
source venv/bin/activate
pip install -r requirements.txt
```

### "No dumps found"

1. Check dumps are in the `dumps/` directory (or your configured DUMPS_DIR)
2. Verify supported format: .zip, .raw, .mem, .dmp, .vmem
3. Check DUMPS_DIR in `config.py` or set via environment variable

### Processing is very slow

- Normal for large dumps (2-3 GB can take 10-15 minutes)
- Results are cached - subsequent queries are instant
- Start with smaller test dumps for development

## Next Steps

- **Technical Details**: See `README.md` in the project directory
- **Multi-LLM Guide**: See `docs/MULTI_LLM_GUIDE.md` for using Ollama/Llama
- **Troubleshooting**: See `docs/TROUBLESHOOTING.md`

## Local LLM Integration

The MCP server is LLM-agnostic and works with any MCP client:

1. The MCP server code stays the same
2. Use the included Ollama client for local LLMs (see docs/MULTI_LLM_GUIDE.md)
3. Swap between Claude and local LLMs anytime
4. Suitable for offline/confidential forensic analysis

---

**Ready to investigate!**
