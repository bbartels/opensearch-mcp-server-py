# Copyright OpenSearch Contributors
# SPDX-License-Identifier: Apache-2.0

import logging
import yaml
from semver import Version


def is_tool_compatible(current_version: Version | None, tool_info: dict = {}):
    """Check if a tool is compatible with the current OpenSearch version.

    Args:
        current_version (Version): The current OpenSearch version
        tool_info (dict): Tool information containing min_version and max_version

    Returns:
        bool: True if the tool is compatible, False otherwise
    """
    # Find a version equivalent in serverless mode
    if not current_version:
        return True
    min_tool_version = Version.parse(
        tool_info.get('min_version', '0.0.0'), optional_minor_and_patch=True
    )
    max_tool_version = Version.parse(
        tool_info.get('max_version', '99.99.99'), optional_minor_and_patch=True
    )
    return min_tool_version <= current_version <= max_tool_version


def parse_comma_separated(text, separator=','):
    """Parse a comma-separated string into a list of trimmed values."""
    if not text:
        return []
    return [item.strip() for item in text.split(separator) if item.strip()]


def load_yaml_config(filter_path):
    """Load and validate YAML configuration file."""
    if not filter_path:
        return None
    try:
        with open(filter_path, 'r') as f:
            config = yaml.safe_load(f)
        if not isinstance(config, dict):
            logging.warning(f'Invalid tool filter configuration in {filter_path}')
            return None
        return config
    except Exception as e:
        logging.error(f'Error loading filter config: {str(e)}')
        return None


def _parse_http_methods(tool_info: dict) -> set:
    """Parse the http_methods field of a tool into a set of uppercase method strings."""
    http_methods = tool_info.get('http_methods', '')
    if isinstance(http_methods, str):
        return {m.strip().upper() for m in http_methods.split(',') if m.strip()}
    return {m.upper() for m in http_methods}


def is_read_only_tool(tool_info: dict) -> bool:
    """Determine if a tool is read-only based on semantic metadata.

    Prefers explicit read_only metadata when present. Falls back to a
    GET-only http_methods heuristic for backward compatibility.

    Args:
        tool_info (dict): Tool metadata containing optional 'read_only'
            and 'http_methods' keys.

    Returns:
        bool: True if the tool is read-only, False otherwise.
    """
    explicit = tool_info.get('read_only')
    if explicit is not None:
        return bool(explicit)

    return _parse_http_methods(tool_info) == {'GET'}


def is_destructive_tool(tool_info: dict) -> bool:
    """Determine if a tool may perform destructive updates to its environment.

    Prefers explicit destructive metadata when present. Falls back to checking
    whether DELETE is among the tool's HTTP methods.

    Per the MCP spec, destructiveHint is meaningful only when readOnlyHint is False.
    Default per spec is True (assume destructive when unknown).

    Args:
        tool_info (dict): Tool metadata containing optional 'destructive'
            and 'http_methods' keys.

    Returns:
        bool: True if the tool may be destructive, False if it is additive-only.
    """
    explicit = tool_info.get('destructive')
    if explicit is not None:
        return bool(explicit)

    return 'DELETE' in _parse_http_methods(tool_info)


def is_idempotent_tool(tool_info: dict) -> bool:
    """Determine if a tool is idempotent (repeated calls with the same arguments
    have no additional effect on its environment).

    Prefers explicit idempotent metadata when present. Falls back to checking
    whether all of the tool's HTTP methods are in the set of HTTP-idempotent
    methods (GET, HEAD, PUT, DELETE).

    Per the MCP spec, idempotentHint is meaningful only when readOnlyHint is False.
    Default per spec is False.

    Args:
        tool_info (dict): Tool metadata containing optional 'idempotent'
            and 'http_methods' keys.

    Returns:
        bool: True if the tool is idempotent, False otherwise.
    """
    explicit = tool_info.get('idempotent')
    if explicit is not None:
        return bool(explicit)

    methods = _parse_http_methods(tool_info)
    return bool(methods) and methods.issubset({'GET', 'HEAD', 'PUT', 'DELETE'})


def validate_tools(tool_list, display_lookup, source_name):
    """Validate tools against registry and return valid tools."""
    valid_tools = set()
    for tool in tool_list:
        tool_lower = tool.lower()
        # Check if it matches tool display name
        if tool_lower in display_lookup:
            actual_tool = display_lookup[tool_lower]
            valid_tools.add(actual_tool.lower())
        else:
            logging.warning(f"Ignoring invalid tool from '{source_name}': '{tool}'")
    return valid_tools
