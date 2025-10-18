# Copyright 2023 The GmSSL Project. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the License); you may
# not use this file except in compliance with the License.
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# GmSSL-Python - SM4 block cipher and modes

"""
Internal module for SM4 block cipher and its modes of operation.
This module should not be imported directly by users.
"""

from ctypes import Structure, byref, c_size_t, c_uint8, c_uint32, c_uint64, create_string_buffer

from gmssl._constants import (
    _SM4_NUM_ROUNDS,
    DO_ENCRYPT,
    SM4_BLOCK_SIZE,
    SM4_GCM_DEFAULT_TAG_SIZE,
    SM4_GCM_MAX_IV_SIZE,
    SM4_GCM_MAX_TAG_SIZE,
    SM4_GCM_MIN_IV_SIZE,
    SM4_KEY_SIZE,
)
from gmssl._lib import NativeError, gmssl

# =============================================================================
# SM4 Block Cipher
# =============================================================================


class Sm4(Structure):
    _fields_ = [("rk", c_uint32 * _SM4_NUM_ROUNDS)]

    def __init__(self, key, encrypt):
        if len(key) != SM4_KEY_SIZE:
            raise ValueError("Invalid key length")
        if encrypt:
            gmssl.sm4_set_encrypt_key(byref(self), key)
        else:
            gmssl.sm4_set_decrypt_key(byref(self), key)

    def encrypt(self, block):
        if len(block) != SM4_BLOCK_SIZE:
            raise ValueError("Invalid block size")
        outbuf = create_string_buffer(SM4_BLOCK_SIZE)
        gmssl.sm4_encrypt(byref(self), block, outbuf)
        return outbuf.raw


# =============================================================================
# SM4-CBC Mode
# =============================================================================


class Sm4Cbc(Structure):
    _fields_ = [
        ("sm4_key", Sm4),
        ("iv", c_uint8 * SM4_BLOCK_SIZE),
        ("block", c_uint8 * SM4_BLOCK_SIZE),
        ("block_nbytes", c_size_t),
    ]

    def __init__(self, key, iv, encrypt):
        if len(key) != SM4_KEY_SIZE:
            raise ValueError("Invalid key length")
        if len(iv) != SM4_BLOCK_SIZE:
            raise ValueError("Invalid IV size")
        if encrypt == DO_ENCRYPT:
            if gmssl.sm4_cbc_encrypt_init(byref(self), key, iv) != 1:
                raise NativeError("libgmssl inner error")
        else:
            if gmssl.sm4_cbc_decrypt_init(byref(self), key, iv) != 1:
                raise NativeError("libgmssl inner error")
        self._encrypt = encrypt

    def update(self, data):
        outbuf = create_string_buffer(len(data) + SM4_BLOCK_SIZE)
        outlen = c_size_t()
        if self._encrypt == DO_ENCRYPT:
            if (
                gmssl.sm4_cbc_encrypt_update(
                    byref(self), data, c_size_t(len(data)), outbuf, byref(outlen)
                )
                != 1
            ):
                raise NativeError("libgmssl inner error")
        else:
            if (
                gmssl.sm4_cbc_decrypt_update(
                    byref(self), data, c_size_t(len(data)), outbuf, byref(outlen)
                )
                != 1
            ):
                raise NativeError("libgmssl inner error")
        return outbuf[0 : outlen.value]

    def finish(self):
        outbuf = create_string_buffer(SM4_BLOCK_SIZE)
        outlen = c_size_t()
        if self._encrypt == DO_ENCRYPT:
            if gmssl.sm4_cbc_encrypt_finish(byref(self), outbuf, byref(outlen)) != 1:
                raise NativeError("libgmssl inner error")
        else:
            if gmssl.sm4_cbc_decrypt_finish(byref(self), outbuf, byref(outlen)) != 1:
                raise NativeError("libgmssl inner error")
        return outbuf[: outlen.value]


# =============================================================================
# SM4-CTR Mode
# =============================================================================


class Sm4Ctr(Structure):
    _fields_ = [
        ("sm4_key", Sm4),
        ("ctr", c_uint8 * SM4_BLOCK_SIZE),
        ("block", c_uint8 * SM4_BLOCK_SIZE),
        ("block_nbytes", c_size_t),
    ]

    def __init__(self, key, ctr):
        if len(key) != SM4_KEY_SIZE:
            raise ValueError("Invalid key length")
        if len(ctr) != SM4_BLOCK_SIZE:
            raise ValueError("Invalid CTR size")
        if gmssl.sm4_ctr_encrypt_init(byref(self), key, ctr) != 1:
            raise NativeError("libgmssl inner error")

    def update(self, data):
        outbuf = create_string_buffer(len(data) + SM4_BLOCK_SIZE)
        outlen = c_size_t()
        if (
            gmssl.sm4_ctr_encrypt_update(
                byref(self), data, c_size_t(len(data)), outbuf, byref(outlen)
            )
            != 1
        ):
            raise NativeError("libgmssl inner error")
        return outbuf[0 : outlen.value]

    def finish(self):
        outbuf = create_string_buffer(SM4_BLOCK_SIZE)
        outlen = c_size_t()
        if gmssl.sm4_ctr_encrypt_finish(byref(self), outbuf, byref(outlen)) != 1:
            raise NativeError("libgmssl inner error")
        return outbuf[: outlen.value]


# =============================================================================
# GCM Mode Support Structures
# =============================================================================


class gf128_t(Structure):
    _fields_ = [("hi", c_uint64), ("lo", c_uint64)]


class Ghash(Structure):
    _fields_ = [
        ("H", gf128_t),
        ("X", gf128_t),
        ("aadlen", c_size_t),
        ("clen", c_size_t),
        ("block", c_uint8 * 16),
        ("num", c_size_t),
    ]


# =============================================================================
# SM4-GCM Mode
# =============================================================================


class Sm4Gcm(Structure):
    _fields_ = [
        ("sm4_ctr_ctx", Sm4Ctr),
        ("mac_ctx", Ghash),
        ("Y", c_uint8 * 16),
        ("taglen", c_size_t),
        ("mac", c_uint8 * 16),
        ("maclen", c_size_t),
        ("encedlen", c_uint64),
    ]

    def __init__(self, key, iv, aad, taglen=SM4_GCM_DEFAULT_TAG_SIZE, encrypt=True):
        if len(key) != SM4_KEY_SIZE:
            raise ValueError("Invalid key length")
        if len(iv) < SM4_GCM_MIN_IV_SIZE or len(iv) > SM4_GCM_MAX_IV_SIZE:
            raise ValueError("Invalid IV size")
        if taglen < 1 or taglen > SM4_GCM_MAX_TAG_SIZE:
            raise ValueError("Invalid Tag length")
        if encrypt == DO_ENCRYPT:
            if (
                gmssl.sm4_gcm_encrypt_init(
                    byref(self),
                    key,
                    c_size_t(len(key)),
                    iv,
                    c_size_t(len(iv)),
                    aad,
                    c_size_t(len(aad)),
                    c_size_t(taglen),
                )
                != 1
            ):
                raise NativeError("libgmssl inner error")
        else:
            if (
                gmssl.sm4_gcm_decrypt_init(
                    byref(self),
                    key,
                    c_size_t(len(key)),
                    iv,
                    c_size_t(len(iv)),
                    aad,
                    c_size_t(len(aad)),
                    c_size_t(taglen),
                )
                != 1
            ):
                raise NativeError("libgmssl inner error")
        self._encrypt = encrypt

    def update(self, data):
        outbuf = create_string_buffer(len(data) + SM4_BLOCK_SIZE)
        outlen = c_size_t()
        if self._encrypt == DO_ENCRYPT:
            if (
                gmssl.sm4_gcm_encrypt_update(
                    byref(self), data, c_size_t(len(data)), outbuf, byref(outlen)
                )
                != 1
            ):
                raise NativeError("libgmssl inner error")
        else:
            if (
                gmssl.sm4_gcm_decrypt_update(
                    byref(self), data, c_size_t(len(data)), outbuf, byref(outlen)
                )
                != 1
            ):
                raise NativeError("libgmssl inner error")
        return outbuf[0 : outlen.value]

    def finish(self):
        outbuf = create_string_buffer(SM4_BLOCK_SIZE + SM4_GCM_MAX_TAG_SIZE)
        outlen = c_size_t()
        if self._encrypt == DO_ENCRYPT:
            if gmssl.sm4_gcm_encrypt_finish(byref(self), outbuf, byref(outlen)) != 1:
                raise NativeError("libgmssl inner error")
        else:
            if gmssl.sm4_gcm_decrypt_finish(byref(self), outbuf, byref(outlen)) != 1:
                raise NativeError("libgmssl inner error")
        return outbuf[: outlen.value]
