# Copyright 2023 The GmSSL Project. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the License); you may
# not use this file except in compliance with the License.
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# GmSSL-Python - Library loading and exceptions

"""
Internal module for GmSSL library loading and exception definitions.
This module should not be imported directly by users.
"""

import os
import platform
import sys
from ctypes import cdll
from ctypes.util import find_library

# =============================================================================
# Library Loading
# =============================================================================

# Minimum required GmSSL version (3.1.1)
REQUIRED_VERSION = 30101
GMSSL_REPO_URL = "https://github.com/guanzhi/GmSSL"


def _get_platform_library_name():
    """
    Get platform-specific library name for bundled GmSSL library.

    Returns:
        str: Library filename for current platform

    Raises:
        ValueError: If platform/architecture is not supported
    """
    if sys.platform == "darwin":
        return "libgmssl.3.dylib"

    if sys.platform == "win32":
        return "gmssl.dll"

    # Linux and other Unix-like systems - detect architecture
    machine = platform.machine().lower()
    if machine in ("aarch64", "arm64"):
        return "libgmssl.so.3.aarch64"

    if machine in ("x86_64", "amd64"):
        return "libgmssl.so.3.x86_64"

    # Unsupported architecture
    raise ValueError(
        f"Unsupported Linux architecture: {machine}\n"
        f"Bundled GmSSL libraries are only available for:\n"
        f"  - x86_64 (amd64)\n"
        f"  - aarch64 (arm64)\n"
        f"Please install GmSSL manually: {GMSSL_REPO_URL}"
    )


def _get_bundled_library_path():
    """
    Get full path to bundled GmSSL library.

    Returns:
        str or None: Path to bundled library if exists, None otherwise
    """
    try:
        lib_name = _get_platform_library_name()
    except ValueError:
        return None

    lib_dir = os.path.join(os.path.dirname(__file__), "_libs")
    lib_path = os.path.join(lib_dir, lib_name)

    return lib_path if os.path.exists(lib_path) else None


def _check_library_version(lib):
    """
    Check if loaded library meets version requirement.

    Args:
        lib: Loaded CDLL library instance

    Returns:
        tuple: (is_valid, version_number)
    """
    version = lib.gmssl_version_num()
    return (version >= REQUIRED_VERSION, version)


def _load_gmssl_library():
    """
    Load GmSSL library with version check and smart fallback.

    Priority:
    1. System library (if version >= 3.1.1)
    2. Bundled library (fallback if system lib too old or missing)

    Returns:
        CDLL: Loaded GmSSL library instance

    Raises:
        ValueError: If no suitable library found or version too old
    """
    # Try system library first
    system_lib_path = find_library("gmssl")
    if system_lib_path:
        lib = cdll.LoadLibrary(system_lib_path)
        is_valid, version = _check_library_version(lib)
        if is_valid:
            return lib
        # System library too old, will try bundled as fallback

    # Try bundled library
    bundled_lib_path = _get_bundled_library_path()
    if bundled_lib_path:
        lib = cdll.LoadLibrary(bundled_lib_path)
        is_valid, version = _check_library_version(lib)
        if is_valid:
            return lib

    # No suitable library found - provide helpful error message
    if system_lib_path:
        # System library exists but too old
        raise ValueError(
            f"GmSSL version too old: {version} < {REQUIRED_VERSION} (required)\n"
            f"Loaded from: {system_lib_path}\n"
            f"Please upgrade GmSSL: {GMSSL_REPO_URL}"
        )

    # No library found at all
    raise ValueError(
        "GmSSL library not found. Install it via:\n"
        f"  - System package: {GMSSL_REPO_URL}\n"
        "  - Or reinstall gmssl_python (should include bundled library)"
    )


# Load GmSSL library
gmssl = _load_gmssl_library()

# Load C standard library for file operations
if sys.platform == "win32":
    libc = cdll.LoadLibrary(find_library("msvcrt"))
else:
    libc = cdll.LoadLibrary(find_library("c"))

# =============================================================================
# Exceptions
# =============================================================================


class NativeError(Exception):
    """
    GmSSL library inner error
    """


class StateError(Exception):
    """
    Crypto state error
    """


# =============================================================================
# Error Handling Utilities
# =============================================================================


def raise_on_error(result, func_name):
    """
    Raise NativeError if gmssl function returns error.

    Args:
        result: Return value from gmssl function (1 = success, other = error)
        func_name: Name of the gmssl function that was called

    Raises:
        NativeError: If result != 1

    Example:
        raise_on_error(gmssl.sm2_key_generate(byref(key)), "sm2_key_generate")
    """
    if result != 1:
        raise NativeError(f"{func_name} failed")
