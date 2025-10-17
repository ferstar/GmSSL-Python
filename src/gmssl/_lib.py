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
import sys
import platform
from ctypes import cdll
from ctypes.util import find_library

# =============================================================================
# Library Loading
# =============================================================================


def _find_gmssl_library():
    """
    Find GmSSL library with the following priority:
    1. System library (via find_library) - respect user's installation
    2. Bundled library (in package _libs/) - convenience for pip users
    3. Fail with clear error message

    This order ensures "Never break userspace" - existing users with
    system-installed GmSSL continue to use their version.

    Returns:
        str: Path to gmssl library

    Raises:
        ValueError: If library not found anywhere
    """
    # Priority 1: System library - NEVER BREAK USERSPACE
    system_lib = find_library("gmssl")
    if system_lib:
        return system_lib

    # Priority 2: Bundled library in package
    lib_dir = os.path.join(os.path.dirname(__file__), "_libs")

    # Platform-specific library names
    if sys.platform == "darwin":
        lib_name = "libgmssl.3.dylib"
    elif sys.platform == "win32":
        lib_name = "gmssl.dll"
    else:  # Linux and other Unix-like systems
        # Detect architecture for Linux
        machine = platform.machine().lower()
        if machine in ("aarch64", "arm64"):
            lib_name = "libgmssl.so.3.aarch64"
        elif machine in ("x86_64", "amd64"):
            lib_name = "libgmssl.so.3.x86_64"
        else:
            # Unsupported architecture - fail fast with clear message
            raise ValueError(
                f"Unsupported Linux architecture: {machine}\n"
                f"Bundled GmSSL libraries are only available for:\n"
                f"  - x86_64 (amd64)\n"
                f"  - aarch64 (arm64)\n"
                f"Please install GmSSL manually: https://github.com/guanzhi/GmSSL"
            )

    bundled_lib = os.path.join(lib_dir, lib_name)
    if os.path.exists(bundled_lib):
        return bundled_lib

    # Priority 3: Both failed - clear error message
    raise ValueError(
        "GmSSL library not found. Install it via:\n"
        "  - System package: https://github.com/guanzhi/GmSSL\n"
        "  - Or reinstall gmssl_python (should include bundled library)"
    )


def _load_gmssl_library():
    """
    Load GmSSL library with version check and smart fallback.

    If system library exists but is too old (< 3.1.1), try bundled library.
    This handles the case where user has outdated system installation.

    Returns:
        CDLL: Loaded GmSSL library instance

    Raises:
        ValueError: If no suitable library found or version too old
    """
    lib_path = _find_gmssl_library()
    lib = cdll.LoadLibrary(lib_path)

    # Check version requirement
    version = lib.gmssl_version_num()
    if version >= 30101:
        return lib

    # Version too old - if this was system library, try bundled as fallback
    system_lib = find_library("gmssl")
    if lib_path == system_lib:
        # Try bundled library with architecture detection
        lib_dir = os.path.join(os.path.dirname(__file__), "_libs")

        if sys.platform == "darwin":
            lib_name = "libgmssl.3.dylib"
        elif sys.platform == "win32":
            lib_name = "gmssl.dll"
        else:  # Linux
            # Detect architecture
            machine = platform.machine().lower()
            if machine in ("aarch64", "arm64"):
                lib_name = "libgmssl.so.3.aarch64"
            elif machine in ("x86_64", "amd64"):
                lib_name = "libgmssl.so.3.x86_64"
            else:
                # Unsupported architecture - no fallback
                raise ValueError(
                    f"Unsupported Linux architecture: {machine}\n"
                    f"Bundled GmSSL libraries are only available for:\n"
                    f"  - x86_64 (amd64)\n"
                    f"  - aarch64 (arm64)\n"
                    f"Please install GmSSL manually: https://github.com/guanzhi/GmSSL"
                )

        bundled_lib = os.path.join(lib_dir, lib_name)
        if os.path.exists(bundled_lib):
            lib = cdll.LoadLibrary(bundled_lib)
            version = lib.gmssl_version_num()
            if version >= 30101:
                return lib

    # No suitable library found
    raise ValueError(
        f"GmSSL version too old: {version} < 30101 (required)\n"
        f"Loaded from: {lib_path}\n"
        f"Please upgrade GmSSL: https://github.com/guanzhi/GmSSL"
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

