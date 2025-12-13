# Memory Forensics MCP Server

AI-powered memory analysis using Volatility 3 and MCP.

## Features

### Core Forensics
- **Process Analysis**: List processes, detect hidden processes, analyze process trees
- **Code Injection Detection**: Identify malicious code injection using malfind
- **Network Analysis**: Correlate network connections with processes
- **Command Line Analysis**: Extract process command lines
- **DLL Analysis**: Examine loaded DLLs per process

### Advanced Capabilities
- **Command Provenance**: Full audit trail of all Volatility commands executed
- **File Integrity**: MD5/SHA1/SHA256 hashing of memory dumps
- **Timeline Analysis**: Chronological event ordering for incident reconstruction
- **Anomaly Detection**: Automated detection of suspicious process behavior
- **Multi-Format Export**: JSON, CSV, and HTML report generation
- **Process Extraction**: Extract detailed process information for offline analysis

## Architecture

```
Memory Dump -> Volatility 3 -> SQLite Cache -> MCP Server -> LLM Client
                                                              (Claude Code/Local LLM)
```

## LLM Compatibility

**This MCP server works with any LLM** The server is LLM-agnostic and communicates via the Model Context Protocol (MCP).

### Supported LLMs

| LLM | Client | Best For |
|-----|--------|----------|
| **Claude** (Opus/Sonnet) | Claude Code | Higher quality analysis |
| **Llama** (via Ollama) | Custom client (included) | Local/offline LLM setup, confidential investigations |
| **GPT-4** | Custom client | OpenAI ecosystem users |
| **Mistral, Phi, others** | Custom client | Custom configs |

### Quick Setup by LLM

**Claude (Easiest):**
- Official Claude Code client with native tool calling support
- Uses `~/.claude/mcp.json` configuration
- See Quick Start section below for setup instructions

**Llama / Ollama:**
```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Pull a model
ollama pull llama3.1:70b

# Start Ollama
ollama serve

# Run the included client
cd examples
pip install -r requirements.txt
python ollama_client.py
```

**Custom LLM:**
- See `examples/ollama_client.py` for reference implementation
- Adapt to your LLM's API
- Full guide: [MULTI_LLM_GUIDE.md](MULTI_LLM_GUIDE.md)

### LLM Profiles

Optimize tool descriptions for different LLM capabilities:

```bash
# For Llama 3.1 70B+
export MCP_LLM_PROFILE=llama70b

# For smaller models (8B-13B)
export MCP_LLM_PROFILE=llama13b

# For minimal models
export MCP_LLM_PROFILE=minimal
```

See [MULTI_LLM_GUIDE.md](MULTI_LLM_GUIDE.md) for comprehensive multi-LLM setup instructions.

## Quick Start

### Prerequisites
- Python 3.8+
- Volatility 3 installed and accessible
- Memory dumps (supported formats: .zip, .raw, .mem, .dmp, .vmem)

### Installation

1. **Clone or download this repository:**
   ```bash
   cd /path/to/your/projects
   git clone <repository-url>
   cd memory-forensics-mcp
   ```

2. **Create virtual environment:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```
   This installs all required dependencies including Volatility 3 from PyPI.

4. **Configure memory dumps directory** (edit `config.py`):
   ```python
   # Set your memory dumps directory
   DUMPS_DIR = Path("/path/to/your/memdumps")
   ```

**Advanced: Using Custom Volatility 3 Installation**

If you need to use a custom Volatility 3 build (e.g., bleeding edge from git):

```bash
# Set environment variable
export VOLATILITY_PATH=/path/to/custom/volatility3

# Or edit config.py directly
# The system will automatically detect and use your custom installation
```

### Configure for Claude Code

Add to `~/.claude/mcp.json`:

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

Replace `/absolute/path/to/memory-forensics-mcp` with your actual installation path.

### Basic Usage with Claude Code

```bash
# Start Claude Code
claude

# Example commands:
"List available memory dumps"
"Process the Win11Dump memory dump"
"Get metadata and hashes for Win11Dump"
"Detect anomalies in Win11Dump"
"Generate a timeline for Win11Dump"
"Export data to JSON format"
```

### Basic Usage with Ollama

```bash
# In one terminal: Start Ollama
ollama serve

# In another terminal: Run the MCP client
cd examples
export MCP_LLM_PROFILE=llama70b
python ollama_client.py
```

## Available Tools

### Core Analysis (8 tools)
| Tool | Description |
|------|-------------|
| `list_dumps` | List available memory dumps |
| `process_dump` | Process a dump with Volatility 3 |
| `list_processes` | List all processes |
| `analyze_process` | Deep dive into specific process |
| `detect_code_injection` | Find injected code |
| `network_analysis` | Analyze network connections |
| `detect_hidden_processes` | Find rootkit-hidden processes |
| `get_process_tree` | Show parent-child relationships |

### Advanced Features (6 tools)
| Tool | Description |
|------|-------------|
| `get_dump_metadata` | Get file hashes, OS info, and statistics |
| `export_data` | Export to JSON, CSV, or HTML formats |
| `get_command_history` | View full command provenance/audit trail |
| `generate_timeline` | Create chronological event timeline |
| `detect_anomalies` | Find suspicious process behavior |
| `extract_process` | Extract detailed process info to file |

## Workflow

### Standard Investigation
1. **List dumps**: See what memory dumps are available
2. **Process dump**: Extract artifacts using Volatility 3 (this takes time!)
3. **Get metadata**: View file hashes and dump statistics
4. **Detect anomalies**: Automated suspicious behavior detection
5. **Generate timeline**: Understand the sequence of events
6. **Export results**: Save findings in JSON/CSV/HTML format

### Example Investigation

```
User: "Analyze the Win11Dump memory dump for signs of compromise"

AI: "Let me process that dump first..."
  > Calls process_dump("Win11Dump")
  > Processes 103 processes, 101 network connections

AI: "Let me check for anomalies..."
  > Calls detect_anomalies("Win11Dump")

AI: "Found critical anomalies:
     - cmd.exe spawned by winword.exe (possible macro exploit)
     - Process 'svch0st.exe' similar to 'svchost.exe' (typosquatting)

     Let me check the timeline..."
  > Calls generate_timeline("Win11Dump")

AI: "Timeline shows suspicious sequence:
     1. winword.exe opens document
     2. cmd.exe spawns 30 seconds later
     3. powershell.exe downloads from external IP

     Let me analyze that PowerShell process..."
  > Calls analyze_process("Win11Dump", 2048)

AI: "This PowerShell process has:
     - Unbacked executable memory (code injection detected)
     - Network connection to suspicious IP 192.0.2.100
     - Base64 encoded command line

     This indicates a fileless malware infection via macro exploit.

     Exporting full report..."
  > Calls export_data("Win11Dump", format="html")

AI: "Complete analysis exported to Win11Dump_report.html"
```

## Data Storage

- **Dumps**: Configured via `DUMPS_DIR` in `config.py` (default: `<project-dir>/dumps/`)
- **Cache**: `<install-dir>/data/artifacts.db` (SQLite database)
- **Exports**: `<install-dir>/data/exports/` (JSON, CSV, HTML reports)
- **Extracted Files**: `<install-dir>/data/extracted/` (extracted process data)
- **Temp extractions**: `/tmp/memdump_*` (auto-cleaned)

## Using with Local LLMs

The MCP server works with any LLM via the Model Context Protocol. For local analysis:

### Quick Start with Ollama

```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Pull Llama model
ollama pull llama3.1:70b

# Start Ollama server
ollama serve

# In another terminal, run the included client
cd /path/to/memory-forensics-mcp/examples
pip install -r requirements.txt
python ollama_client.py
```

### Customization

- **Example client**: See `examples/ollama_client.py` for a complete reference implementation
- **LLM profiles**: Use `MCP_LLM_PROFILE` environment variable to optimize for different model sizes
- **Full guide**: See [MULTI_LLM_GUIDE.md](MULTI_LLM_GUIDE.md) for comprehensive setup instructions for Llama, GPT-4, and other LLMs

**Benefits of local LLMs:**
- Complete privacy - no data sent to cloud services
- Free to use after initial setup (no API costs)
- Suitable for confidential investigations and offline environments

## Performance Notes

- Initial processing of a dump (2-3 GB) takes 5-15 minutes
- Results are cached in SQLite for instant subsequent queries
- Consider processing dumps offline, then analyze interactively

## Troubleshooting

**"Volatility import error"**
- Ensure volatility3 is installed: `pip install -r requirements.txt`
- For custom installations, check VOLATILITY_PATH environment variable or config.py
- Verify import works: `python -c "import volatility3; print('OK')"`

**"No dumps found"**
- Check `DUMPS_DIR` in `config.py`
- Supported formats: .zip, .raw, .mem, .dmp, .vmem

**"Processing very slow"**
- Normal for large dumps
- Consider running `process_dump` once, then all queries are fast
- Use smaller test dumps for development

## License

This is a research/educational tool. Ensure you have authorization before analyzing any memory dumps.
