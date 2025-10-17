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

import sys
from ctypes import cdll
from ctypes.util import find_library

# =============================================================================
# Library Loading
# =============================================================================

if find_library("gmssl") is None:
    raise ValueError("Install GmSSL dynamic library from https://github.com/guanzhi/GmSSL")
gmssl = cdll.LoadLibrary(find_library("gmssl"))
if gmssl.gmssl_version_num() < 30101:
    raise ValueError("GmSSL version < 3.1.1")

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

