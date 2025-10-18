# Copyright 2023 The GmSSL Project. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the License); you may
# not use this file except in compliance with the License.
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# GmSSL-Python - PEM file utilities for Windows compatibility

"""
Internal module for PEM file operations with Windows FILE* workaround.
This module should not be imported directly by users.

On Windows, FILE* pointers cannot be passed across DLL boundaries due to
different C runtime versions. This module provides Python-based PEM I/O
that works around this limitation by using DER format + base64 encoding.

For Linux/macOS, this module provides wrapper functions that delegate to
the native FILE*-based functions for best performance.
"""

import base64
import sys
from ctypes import POINTER, byref, c_char_p, c_size_t, c_uint8, c_void_p, create_string_buffer

from gmssl._file_utils import open_file
from gmssl._lib import NativeError, gmssl, libc


def _write_pem_windows(path, name, der_data):
    """
    Write PEM file on Windows using Python file I/O.

    Args:
        path: File path (str)
        name: PEM label (e.g., "ENCRYPTED PRIVATE KEY")
        der_data: DER-encoded data (bytes)
    """
    with open(path, "wb") as f:
        f.write(f"-----BEGIN {name}-----\n".encode("ascii"))
        # Base64 encode with 64 characters per line (PEM standard)
        b64_data = base64.b64encode(der_data)
        for i in range(0, len(b64_data), 64):
            f.write(b64_data[i : i + 64])
            f.write(b"\n")
        f.write(f"-----END {name}-----\n".encode("ascii"))


def _read_pem_windows(path, name):
    """
    Read PEM file on Windows using Python file I/O.

    Args:
        path: File path (str)
        name: PEM label (e.g., "ENCRYPTED PRIVATE KEY")

    Returns:
        bytes: DER-encoded data
    """
    begin_marker = f"-----BEGIN {name}-----"
    end_marker = f"-----END {name}-----"

    with open(path) as f:
        lines = f.readlines()

    # Find begin and end markers
    begin_idx = None
    end_idx = None
    for i, line in enumerate(lines):
        line = line.strip()
        if line == begin_marker:
            begin_idx = i
        elif line == end_marker:
            end_idx = i
            break

    if begin_idx is None or end_idx is None:
        raise ValueError(f"Invalid PEM file: missing {name} markers")

    # Extract base64 data
    b64_data = "".join(line.strip() for line in lines[begin_idx + 1 : end_idx])
    return base64.b64decode(b64_data)


# =============================================================================
# SM2 Key PEM Operations
# =============================================================================


def sm2_private_key_info_encrypt_to_pem_windows(key, path, passwd):
    """
    Export SM2 encrypted private key to PEM file (Windows-compatible).

    Uses DER export + Python file I/O to avoid FILE* cross-DLL issues.
    """
    # Export to DER format
    out_ptr = POINTER(c_uint8)()
    outlen = c_size_t()

    if (
        gmssl.sm2_private_key_info_encrypt_to_der(
            byref(key), c_char_p(passwd), byref(out_ptr), byref(outlen)
        )
        != 1
    ):
        raise NativeError("sm2_private_key_info_encrypt_to_der failed")

    try:
        # Copy DER data to Python bytes
        der_data = create_string_buffer(outlen.value)
        libc.memcpy(der_data, out_ptr, outlen.value)

        # Write PEM file
        _write_pem_windows(path, "ENCRYPTED PRIVATE KEY", der_data.raw)
    finally:
        # Free allocated memory
        libc.free(out_ptr)


def sm2_private_key_info_decrypt_from_pem_windows(key, path, passwd):
    """
    Import SM2 encrypted private key from PEM file (Windows-compatible).
    """
    # Read PEM file and decode to DER
    der_data = _read_pem_windows(path, "ENCRYPTED PRIVATE KEY")

    # Parse DER format
    der_ptr = c_char_p(der_data)
    der_len = c_size_t(len(der_data))
    attrs_ptr = c_void_p()
    attrs_len = c_size_t()

    if (
        gmssl.sm2_private_key_info_decrypt_from_der(
            byref(key),
            byref(attrs_ptr),
            byref(attrs_len),
            c_char_p(passwd),
            byref(der_ptr),
            byref(der_len),
        )
        != 1
    ):
        raise NativeError("sm2_private_key_info_decrypt_from_der failed")


# =============================================================================
# SM9 Encryption Master Key PEM Operations
# =============================================================================


def sm9_enc_master_key_info_encrypt_to_pem_windows(msk, path, passwd):
    """
    Export SM9 encryption master key to PEM file (Windows-compatible).
    """
    out_ptr = POINTER(c_uint8)()
    outlen = c_size_t()

    if (
        gmssl.sm9_enc_master_key_info_encrypt_to_der(
            byref(msk), c_char_p(passwd), byref(out_ptr), byref(outlen)
        )
        != 1
    ):
        raise NativeError("sm9_enc_master_key_info_encrypt_to_der failed")

    try:
        der_data = create_string_buffer(outlen.value)
        libc.memcpy(der_data, out_ptr, outlen.value)
        _write_pem_windows(path, "ENCRYPTED PRIVATE KEY", der_data.raw)
    finally:
        libc.free(out_ptr)


def sm9_enc_master_key_info_decrypt_from_pem_windows(msk, path, passwd):
    """
    Import SM9 encryption master key from PEM file (Windows-compatible).
    """
    der_data = _read_pem_windows(path, "ENCRYPTED PRIVATE KEY")
    der_ptr = c_char_p(der_data)
    der_len = c_size_t(len(der_data))

    if (
        gmssl.sm9_enc_master_key_info_decrypt_from_der(
            byref(msk), c_char_p(passwd), byref(der_ptr), byref(der_len)
        )
        != 1
    ):
        raise NativeError("sm9_enc_master_key_info_decrypt_from_der failed")


# =============================================================================
# SM9 Signature Master Key PEM Operations
# =============================================================================


def sm9_sign_master_key_info_encrypt_to_pem_windows(msk, path, passwd):
    """
    Export SM9 signature master key to PEM file (Windows-compatible).
    """
    out_ptr = POINTER(c_uint8)()
    outlen = c_size_t()

    if (
        gmssl.sm9_sign_master_key_info_encrypt_to_der(
            byref(msk), c_char_p(passwd), byref(out_ptr), byref(outlen)
        )
        != 1
    ):
        raise NativeError("sm9_sign_master_key_info_encrypt_to_der failed")

    try:
        der_data = create_string_buffer(outlen.value)
        libc.memcpy(der_data, out_ptr, outlen.value)
        _write_pem_windows(path, "ENCRYPTED PRIVATE KEY", der_data.raw)
    finally:
        libc.free(out_ptr)


def sm9_sign_master_key_info_decrypt_from_pem_windows(msk, path, passwd):
    """
    Import SM9 signature master key from PEM file (Windows-compatible).
    """
    der_data = _read_pem_windows(path, "ENCRYPTED PRIVATE KEY")
    der_ptr = c_char_p(der_data)
    der_len = c_size_t(len(der_data))

    if (
        gmssl.sm9_sign_master_key_info_decrypt_from_der(
            byref(msk), c_char_p(passwd), byref(der_ptr), byref(der_len)
        )
        != 1
    ):
        raise NativeError("sm9_sign_master_key_info_decrypt_from_der failed")


# =============================================================================
# SM9 Encryption Key PEM Operations
# =============================================================================


def sm9_enc_key_info_encrypt_to_pem_windows(key, path, passwd):
    """
    Export SM9 encryption key to PEM file (Windows-compatible).
    """
    out_ptr = POINTER(c_uint8)()
    outlen = c_size_t()

    if (
        gmssl.sm9_enc_key_info_encrypt_to_der(
            byref(key), c_char_p(passwd), byref(out_ptr), byref(outlen)
        )
        != 1
    ):
        raise NativeError("sm9_enc_key_info_encrypt_to_der failed")

    try:
        der_data = create_string_buffer(outlen.value)
        libc.memcpy(der_data, out_ptr, outlen.value)
        _write_pem_windows(path, "ENCRYPTED PRIVATE KEY", der_data.raw)
    finally:
        libc.free(out_ptr)


def sm9_enc_key_info_decrypt_from_pem_windows(key, path, passwd):
    """
    Import SM9 encryption key from PEM file (Windows-compatible).
    """
    der_data = _read_pem_windows(path, "ENCRYPTED PRIVATE KEY")
    der_ptr = c_char_p(der_data)
    der_len = c_size_t(len(der_data))

    if (
        gmssl.sm9_enc_key_info_decrypt_from_der(
            byref(key), c_char_p(passwd), byref(der_ptr), byref(der_len)
        )
        != 1
    ):
        raise NativeError("sm9_enc_key_info_decrypt_from_der failed")


# =============================================================================
# SM9 Signature Key PEM Operations
# =============================================================================


def sm9_sign_key_info_encrypt_to_pem_windows(key, path, passwd):
    """
    Export SM9 signature key to PEM file (Windows-compatible).
    """
    out_ptr = POINTER(c_uint8)()
    outlen = c_size_t()

    if (
        gmssl.sm9_sign_key_info_encrypt_to_der(
            byref(key), c_char_p(passwd), byref(out_ptr), byref(outlen)
        )
        != 1
    ):
        raise NativeError("sm9_sign_key_info_encrypt_to_der failed")

    try:
        der_data = create_string_buffer(outlen.value)
        libc.memcpy(der_data, out_ptr, outlen.value)
        _write_pem_windows(path, "ENCRYPTED PRIVATE KEY", der_data.raw)
    finally:
        libc.free(out_ptr)


def sm9_sign_key_info_decrypt_from_pem_windows(key, path, passwd):
    """
    Import SM9 signature key from PEM file (Windows-compatible).
    """
    der_data = _read_pem_windows(path, "ENCRYPTED PRIVATE KEY")
    der_ptr = c_char_p(der_data)
    der_len = c_size_t(len(der_data))

    if (
        gmssl.sm9_sign_key_info_decrypt_from_der(
            byref(key), c_char_p(passwd), byref(der_ptr), byref(der_len)
        )
        != 1
    ):
        raise NativeError("sm9_sign_key_info_decrypt_from_der failed")


# =============================================================================
# Cross-Platform Wrapper Functions
# =============================================================================


def pem_export_encrypted_key(key, path, passwd, export_func_name):
    """
    Cross-platform wrapper for exporting encrypted keys to PEM.

    Automatically selects Windows-compatible or FILE*-based implementation.
    Windows function name is derived by appending '_windows' to export_func_name.

    Args:
        key: Key object (SM2Key, Sm9EncMasterKey, etc.)
        path: File path (str)
        passwd: Password (bytes)
        export_func_name: Name of the gmssl export function
                         (e.g., "sm2_private_key_info_encrypt_to_pem")
    """
    if sys.platform == "win32":
        # Automatically derive Windows function name
        windows_func_name = f"{export_func_name}_windows"
        windows_func = globals()[windows_func_name]
        windows_func(key, path, passwd)
    else:
        # Linux/macOS: Use FILE* for best performance
        with open_file(path, "wb") as fp:
            if getattr(gmssl, export_func_name)(byref(key), c_char_p(passwd), fp) != 1:
                raise NativeError(f"{export_func_name} failed")


def pem_import_encrypted_key(key, path, passwd, import_func_name):
    """
    Cross-platform wrapper for importing encrypted keys from PEM.

    Automatically selects Windows-compatible or FILE*-based implementation.
    Windows function name is derived by appending '_windows' to import_func_name.

    Args:
        key: Key object (SM2Key, Sm9EncMasterKey, etc.)
        path: File path (str)
        passwd: Password (bytes)
        import_func_name: Name of the gmssl import function
                         (e.g., "sm2_private_key_info_decrypt_from_pem")
    """
    if sys.platform == "win32":
        # Automatically derive Windows function name
        windows_func_name = f"{import_func_name}_windows"
        windows_func = globals()[windows_func_name]
        windows_func(key, path, passwd)
    else:
        # Linux/macOS: Use FILE* for best performance
        with open_file(path, "rb") as fp:
            if getattr(gmssl, import_func_name)(byref(key), c_char_p(passwd), fp) != 1:
                raise NativeError(f"{import_func_name} failed")
