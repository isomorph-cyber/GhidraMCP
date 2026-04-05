# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "requests>=2,<3",
#     "mcp>=1.2.0,<2",
# ]
# ///

import sys
import json
import requests
import argparse
import logging
from urllib.parse import urljoin

from mcp.server.fastmcp import FastMCP

DEFAULT_GHIDRA_SERVER = "http://127.0.0.1:8080/"

logger = logging.getLogger(__name__)

mcp = FastMCP("ghidra-mcp")

# Initialize ghidra_server_url with default value
ghidra_server_url = DEFAULT_GHIDRA_SERVER

def safe_get(endpoint: str, params: dict = None) -> list:
    """
    Perform a GET request with optional query parameters.
    """
    if params is None:
        params = {}

    url = urljoin(ghidra_server_url, endpoint)

    try:
        response = requests.get(url, params=params, timeout=5)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.splitlines()
        else:
            return [f"Error {response.status_code}: {response.text.strip()}"]
    except Exception as e:
        return [f"Request failed: {str(e)}"]

def safe_post(endpoint: str, data: dict | str) -> str:
    try:
        url = urljoin(ghidra_server_url, endpoint)
        if isinstance(data, dict):
            response = requests.post(url, data=data, timeout=5)
        else:
            response = requests.post(url, data=data.encode("utf-8"), timeout=5)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.strip()
        else:
            return f"Error {response.status_code}: {response.text.strip()}"
    except Exception as e:
        return f"Request failed: {str(e)}"

@mcp.tool()
def list_methods(offset: int = 0, limit: int = 100) -> list:
    """
    List all function names in the program with pagination.
    """
    return safe_get("methods", {"offset": offset, "limit": limit})

@mcp.tool()
def list_classes(offset: int = 0, limit: int = 100) -> list:
    """
    List all namespace/class names in the program with pagination.
    """
    return safe_get("classes", {"offset": offset, "limit": limit})

@mcp.tool()
def decompile_function(name: str) -> str:
    """
    Decompile a specific function by name and return the decompiled C code.
    """
    return safe_post("decompile", name)

@mcp.tool()
def rename_function(old_name: str, new_name: str) -> str:
    """
    Rename a function by its current name to a new user-defined name.
    """
    return safe_post("renameFunction", {"oldName": old_name, "newName": new_name})

@mcp.tool()
def rename_data(address: str, new_name: str) -> str:
    """
    Rename a data label at the specified address.
    """
    return safe_post("renameData", {"address": address, "newName": new_name})

@mcp.tool()
def list_segments(offset: int = 0, limit: int = 100) -> list:
    """
    List all memory segments in the program with pagination.
    """
    return safe_get("segments", {"offset": offset, "limit": limit})

@mcp.tool()
def list_imports(offset: int = 0, limit: int = 100) -> list:
    """
    List imported symbols in the program with pagination.
    """
    return safe_get("imports", {"offset": offset, "limit": limit})

@mcp.tool()
def list_exports(offset: int = 0, limit: int = 100) -> list:
    """
    List exported functions/symbols with pagination.
    """
    return safe_get("exports", {"offset": offset, "limit": limit})

@mcp.tool()
def list_namespaces(offset: int = 0, limit: int = 100) -> list:
    """
    List all non-global namespaces in the program with pagination.
    """
    return safe_get("namespaces", {"offset": offset, "limit": limit})

@mcp.tool()
def list_data_items(offset: int = 0, limit: int = 100) -> list:
    """
    List defined data labels and their values with pagination.
    """
    return safe_get("data", {"offset": offset, "limit": limit})

@mcp.tool()
def search_functions_by_name(query: str, offset: int = 0, limit: int = 100) -> list:
    """
    Search for functions whose name contains the given substring.
    """
    if not query:
        return ["Error: query string is required"]
    return safe_get("searchFunctions", {"query": query, "offset": offset, "limit": limit})

@mcp.tool()
def rename_variable(function_name: str, old_name: str, new_name: str) -> str:
    """
    Rename a local variable within a function.
    """
    return safe_post("renameVariable", {
        "functionName": function_name,
        "oldName": old_name,
        "newName": new_name
    })

@mcp.tool()
def get_function_by_address(address: str) -> str:
    """
    Get a function by its address.
    """
    return "\n".join(safe_get("get_function_by_address", {"address": address}))

@mcp.tool()
def get_current_address() -> str:
    """
    Get the address currently selected by the user.
    """
    return "\n".join(safe_get("get_current_address"))

@mcp.tool()
def get_current_function() -> str:
    """
    Get the function currently selected by the user.
    """
    return "\n".join(safe_get("get_current_function"))

@mcp.tool()
def list_functions() -> list:
    """
    List all functions in the database.
    """
    return safe_get("list_functions")

@mcp.tool()
def decompile_function_by_address(address: str) -> str:
    """
    Decompile a function at the given address.
    """
    return "\n".join(safe_get("decompile_function", {"address": address}))

@mcp.tool()
def disassemble_function(address: str) -> list:
    """
    Get assembly code (address: instruction; comment) for a function.
    """
    return safe_get("disassemble_function", {"address": address})

@mcp.tool()
def set_decompiler_comment(address: str, comment: str) -> str:
    """
    Set a comment for a given address in the function pseudocode.
    """
    return safe_post("set_decompiler_comment", {"address": address, "comment": comment})

@mcp.tool()
def set_disassembly_comment(address: str, comment: str) -> str:
    """
    Set a comment for a given address in the function disassembly.
    """
    return safe_post("set_disassembly_comment", {"address": address, "comment": comment})

@mcp.tool()
def rename_function_by_address(function_address: str, new_name: str) -> str:
    """
    Rename a function by its address.
    """
    return safe_post("rename_function_by_address", {"function_address": function_address, "new_name": new_name})

@mcp.tool()
def set_function_prototype(function_address: str, prototype: str) -> str:
    """
    Set a function's prototype.
    """
    return safe_post("set_function_prototype", {"function_address": function_address, "prototype": prototype})

@mcp.tool()
def set_local_variable_type(function_address: str, variable_name: str, new_type: str) -> str:
    """
    Set a local variable's type.
    """
    return safe_post("set_local_variable_type", {"function_address": function_address, "variable_name": variable_name, "new_type": new_type})

@mcp.tool()
def get_xrefs_to(address: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references to the specified address (xref to).
    
    Args:
        address: Target address in hex format (e.g. "0x1400010a0")
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references to the specified address
    """
    return safe_get("xrefs_to", {"address": address, "offset": offset, "limit": limit})

@mcp.tool()
def get_xrefs_from(address: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references from the specified address (xref from).
    
    Args:
        address: Source address in hex format (e.g. "0x1400010a0")
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references from the specified address
    """
    return safe_get("xrefs_from", {"address": address, "offset": offset, "limit": limit})

@mcp.tool()
def get_function_xrefs(name: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references to the specified function by name.
    
    Args:
        name: Function name to search for
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references to the specified function
    """
    return safe_get("function_xrefs", {"name": name, "offset": offset, "limit": limit})

@mcp.tool()
def list_strings(offset: int = 0, limit: int = 2000, filter: str = None) -> list:
    """
    List all defined strings in the program with their addresses.
    
    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum number of strings to return (default: 2000)
        filter: Optional filter to match within string content
        
    Returns:
        List of strings with their addresses
    """
    params = {"offset": offset, "limit": limit}
    if filter:
        params["filter"] = filter
    return safe_get("strings", params)

# ---------------------------------------------------------------------------
# Dynamic script-based tool registration
# ---------------------------------------------------------------------------

_dynamic_tool_names: set = set()

_TYPE_MAP = {
    "str": "str", "string": "str", "path": "str",
    "int": "int", "integer": "int",
    "float": "float", "number": "float",
    "bool": "bool", "boolean": "bool",
    "list": "list", "dict": "dict",
}


def _fetch_scripts() -> list:
    """GET /scripts from the Ghidra plugin, return list of entries."""
    url = urljoin(ghidra_server_url, "scripts")
    try:
        response = requests.get(url, timeout=10)
        response.encoding = "utf-8"
        if response.ok:
            data = response.json()
            return data.get("scripts", [])
        logger.warning("Scripts endpoint returned %s: %s", response.status_code, response.text[:200])
    except Exception as e:
        logger.warning("Could not fetch scripts: %s", e)
    return []


def _call_script(script_name: str, args: dict, timeout_ms: int = 180000) -> dict:
    """POST /run_script — runs script_name with args (passed as JSON)."""
    url = urljoin(ghidra_server_url, "run_script")
    payload = {
        "name": script_name,
        "args_json": json.dumps(args),
        "timeout_ms": str(timeout_ms),
    }
    try:
        response = requests.post(url, data=payload, timeout=(timeout_ms / 1000) + 15)
        response.encoding = "utf-8"
        if response.ok:
            try:
                return response.json()
            except Exception:
                return {"ok": False, "error": "invalid json response", "raw": response.text}
        return {"ok": False, "error": "HTTP %s" % response.status_code, "raw": response.text}
    except Exception as e:
        return {"ok": False, "error": "request failed: %s" % e}


def _build_tool_fn(script_name: str, tool_name: str, description: str, args_schema: list):
    """Build a typed Python function that forwards to _call_script."""
    params = []
    for a in args_schema:
        py_type = _TYPE_MAP.get((a.get("type") or "str").lower(), "str")
        params.append("%s: %s" % (a["name"], py_type))
    sig = ", ".join(params) if params else ""
    args_dict = "{" + ", ".join('"%s": %s' % (a["name"], a["name"]) for a in args_schema) + "}"

    doc_body = (description or ("Runs Ghidra script " + script_name)).replace('"""', "'''")
    args_doc = "\n".join(
        '        %s (%s): %s' % (a["name"], a.get("type", "str"), a.get("description", ""))
        for a in args_schema
    )
    src = 'def dynamic_tool(%s) -> dict:\n' % sig
    src += '    """%s\n' % doc_body
    if args_doc:
        src += '\n    Args:\n' + args_doc + '\n'
    src += '    """\n'
    src += '    return _call_script(%r, %s)\n' % (script_name, args_dict)

    ns = {"_call_script": _call_script}
    exec(src, ns)
    fn = ns["dynamic_tool"]
    fn.__name__ = tool_name
    return fn


def _register_script_tool(entry: dict) -> bool:
    tool_name = entry.get("mcp_tool")
    if not tool_name:
        return False
    script_name = entry.get("name") or ""
    description = entry.get("description") or ("Runs Ghidra script " + script_name)
    args_schema = entry.get("mcp_args") or []
    try:
        fn = _build_tool_fn(script_name, tool_name, description, args_schema)
        if tool_name in _dynamic_tool_names:
            try:
                mcp.remove_tool(tool_name)
            except Exception:
                pass
        mcp.add_tool(fn, name=tool_name, description=description)
        _dynamic_tool_names.add(tool_name)
        return True
    except Exception as e:
        logger.warning("Failed to register tool %s: %s", tool_name, e)
        return False


def _register_all_scripts() -> int:
    entries = _fetch_scripts()
    count = 0
    for entry in entries:
        if _register_script_tool(entry):
            count += 1
    logger.info("Registered %d dynamic script tools", count)
    return count


@mcp.tool()
def refresh_ghidra_scripts() -> dict:
    """
    Re-scan Ghidra script directories and update dynamic MCP tools in place.

    Add a new script with @mcp-tool / @mcp-arg headers, then call this tool
    to pick it up without restarting MCP. Returns the added/removed tool names.
    """
    entries = _fetch_scripts()
    current = {e["mcp_tool"]: e for e in entries if e.get("mcp_tool")}

    added: list = []
    removed: list = []
    updated: list = []

    for existing in list(_dynamic_tool_names):
        if existing not in current:
            try:
                mcp.remove_tool(existing)
                _dynamic_tool_names.discard(existing)
                removed.append(existing)
            except Exception as e:
                logger.warning("remove_tool(%s) failed: %s", existing, e)

    for tname, entry in current.items():
        was_present = tname in _dynamic_tool_names
        if _register_script_tool(entry):
            (updated if was_present else added).append(tname)

    try:
        mcp._mcp_server._tool_cache.clear()
    except Exception:
        pass

    try:
        import asyncio
        ctx = mcp.get_context()
        asyncio.ensure_future(ctx.session.send_tool_list_changed())
    except Exception as e:
        logger.debug("send_tool_list_changed failed: %s", e)

    return {
        "added": added,
        "removed": removed,
        "updated": updated,
        "total": len(_dynamic_tool_names),
    }


@mcp.tool()
def run_ghidra_script(name: str, args_json: str = "{}", timeout_ms: int = 180000) -> dict:
    """
    Generic escape hatch: run any Ghidra script by name.

    Use this if a script has no @mcp-tool headers yet, or for one-off runs.
    Args are passed as a JSON string and forwarded to the script via
    GhidraState env var GHIDRA_MCP_ARGS plus script args --mcp-args <json>.
    """
    try:
        args = json.loads(args_json) if args_json else {}
    except Exception as e:
        return {"ok": False, "error": "invalid args_json: %s" % e}
    return _call_script(name, args, timeout_ms=timeout_ms)


@mcp.tool()
def list_ghidra_scripts() -> list:
    """
    List all Ghidra scripts in the user/system script source directories,
    including parsed @mcp-tool / @mcp-arg / @category metadata.
    """
    return _fetch_scripts()


def main():
    parser = argparse.ArgumentParser(description="MCP server for Ghidra")
    parser.add_argument("--ghidra-server", type=str, default=DEFAULT_GHIDRA_SERVER,
                        help=f"Ghidra server URL, default: {DEFAULT_GHIDRA_SERVER}")
    parser.add_argument("--mcp-host", type=str, default="127.0.0.1",
                        help="Host to run MCP server on (only used for sse), default: 127.0.0.1")
    parser.add_argument("--mcp-port", type=int,
                        help="Port to run MCP server on (only used for sse), default: 8081")
    parser.add_argument("--transport", type=str, default="stdio", choices=["stdio", "sse"],
                        help="Transport protocol for MCP, default: stdio")
    args = parser.parse_args()
    
    # Use the global variable to ensure it's properly updated
    global ghidra_server_url
    if args.ghidra_server:
        ghidra_server_url = args.ghidra_server

    # Best-effort dynamic tool registration: scan scripts and add MCP tools
    # for any script with @mcp-tool headers. Silently skips if Ghidra/plugin
    # isn't running yet — user can call refresh_ghidra_scripts later.
    try:
        _register_all_scripts()
    except Exception as e:
        logger.warning("Initial script scan failed: %s", e)

    if args.transport == "sse":
        try:
            # Set up logging
            log_level = logging.INFO
            logging.basicConfig(level=log_level)
            logging.getLogger().setLevel(log_level)

            # Configure MCP settings
            mcp.settings.log_level = "INFO"
            if args.mcp_host:
                mcp.settings.host = args.mcp_host
            else:
                mcp.settings.host = "127.0.0.1"

            if args.mcp_port:
                mcp.settings.port = args.mcp_port
            else:
                mcp.settings.port = 8081

            logger.info(f"Connecting to Ghidra server at {ghidra_server_url}")
            logger.info(f"Starting MCP server on http://{mcp.settings.host}:{mcp.settings.port}/sse")
            logger.info(f"Using transport: {args.transport}")

            mcp.run(transport="sse")
        except KeyboardInterrupt:
            logger.info("Server stopped by user")
    else:
        mcp.run()
        
if __name__ == "__main__":
    main()

