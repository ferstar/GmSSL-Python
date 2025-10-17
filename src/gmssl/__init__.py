# Copyright 2023 The GmSSL Project. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the License); you may
# not use this file except in compliance with the License.
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# GmSSL-Python - Python binding of the GmSSL library with `ctypes`

"""
GmSSL Python Binding

This package provides Python bindings for the GmSSL cryptographic library.
All cryptographic operations are implemented by calling the native GmSSL
dynamic library through ctypes.

Following Linus's philosophy: "Bad programmers worry about the code.
Good programmers worry about data structures and their relationships."

This module exports a clean, minimal public API. Internal implementation
details are kept in _core module.
"""

# Import all public APIs from the core implementation
from gmssl._core import (
    # SM2 Public Key Cryptography
    DO_DECRYPT,
    DO_ENCRYPT,
    DO_SIGN,
    DO_VERIFY,
    # Version information
    GMSSL_LIBRARY_VERSION,
    GMSSL_PYTHON_VERSION,
    SM2_DEFAULT_ID,
    SM2_MAX_CIPHERTEXT_SIZE,
    SM2_MAX_PLAINTEXT_SIZE,
    SM2_MAX_SIGNATURE_SIZE,
    SM2_MIN_CIPHERTEXT_SIZE,
    SM2_MIN_PLAINTEXT_SIZE,
    # SM3 Hash
    SM3_DIGEST_SIZE,
    SM3_HMAC_MAX_KEY_SIZE,
    SM3_HMAC_MIN_KEY_SIZE,
    SM3_HMAC_SIZE,
    SM3_PBKDF2_DEFAULT_SALT_SIZE,
    SM3_PBKDF2_MAX_ITER,
    SM3_PBKDF2_MAX_KEY_SIZE,
    SM3_PBKDF2_MAX_SALT_SIZE,
    SM3_PBKDF2_MIN_ITER,
    # SM4 Block Cipher
    SM4_BLOCK_SIZE,
    SM4_CBC_IV_SIZE,
    SM4_CTR_IV_SIZE,
    SM4_GCM_DEFAULT_IV_SIZE,
    SM4_GCM_DEFAULT_TAG_SIZE,
    SM4_GCM_MAX_IV_SIZE,
    SM4_GCM_MAX_TAG_SIZE,
    SM4_GCM_MIN_IV_SIZE,
    SM4_KEY_SIZE,
    # SM9 Identity-Based Cryptography
    SM9_MAX_CIPHERTEXT_SIZE,
    SM9_MAX_ID_SIZE,
    SM9_MAX_PLAINTEXT_SIZE,
    SM9_SIGNATURE_SIZE,
    # ZUC Stream Cipher
    ZUC_IV_SIZE,
    ZUC_KEY_SIZE,
    # Exceptions
    NativeError,
    Sm2Certificate,
    Sm2Key,
    Sm2Signature,
    Sm3,
    Sm3Hmac,
    Sm4,
    Sm4Cbc,
    Sm4Ctr,
    Sm4Gcm,
    Sm9EncMasterKey,
    Sm9Signature,
    Sm9SignMasterKey,
    StateError,
    # X.509 Certificate Parsing Utilities
    Validity,
    Zuc,
    gmssl_library_version_num,
    gmssl_library_version_str,
    gmssl_parse_attr_type_and_value,
    gmssl_parse_name,
    gmssl_parse_rdn,
    # Random number generator
    rand_bytes,
    sm3_pbkdf2,
)

# Explicit public API declaration
# Following Python convention: if __all__ is defined, only these names are exported
__all__ = [
    # Version information
    "GMSSL_LIBRARY_VERSION",
    "GMSSL_PYTHON_VERSION",
    "gmssl_library_version_num",
    "gmssl_library_version_str",
    # Exceptions
    "NativeError",
    "StateError",
    # Random number generator
    "rand_bytes",
    # SM3 Hash
    "SM3_DIGEST_SIZE",
    "SM3_HMAC_MAX_KEY_SIZE",
    "SM3_HMAC_MIN_KEY_SIZE",
    "SM3_HMAC_SIZE",
    "SM3_PBKDF2_DEFAULT_SALT_SIZE",
    "SM3_PBKDF2_MAX_ITER",
    "SM3_PBKDF2_MAX_KEY_SIZE",
    "SM3_PBKDF2_MAX_SALT_SIZE",
    "SM3_PBKDF2_MIN_ITER",
    "Sm3",
    "Sm3Hmac",
    "sm3_pbkdf2",
    # SM4 Block Cipher
    "SM4_BLOCK_SIZE",
    "SM4_CBC_IV_SIZE",
    "SM4_CTR_IV_SIZE",
    "SM4_GCM_DEFAULT_IV_SIZE",
    "SM4_GCM_DEFAULT_TAG_SIZE",
    "SM4_GCM_MAX_IV_SIZE",
    "SM4_GCM_MAX_TAG_SIZE",
    "SM4_GCM_MIN_IV_SIZE",
    "SM4_KEY_SIZE",
    "Sm4",
    "Sm4Cbc",
    "Sm4Ctr",
    "Sm4Gcm",
    # ZUC Stream Cipher
    "ZUC_IV_SIZE",
    "ZUC_KEY_SIZE",
    "Zuc",
    # SM2 Public Key Cryptography
    "DO_DECRYPT",
    "DO_ENCRYPT",
    "DO_SIGN",
    "DO_VERIFY",
    "SM2_DEFAULT_ID",
    "SM2_MAX_CIPHERTEXT_SIZE",
    "SM2_MAX_PLAINTEXT_SIZE",
    "SM2_MAX_SIGNATURE_SIZE",
    "SM2_MIN_CIPHERTEXT_SIZE",
    "SM2_MIN_PLAINTEXT_SIZE",
    "Sm2Certificate",
    "Sm2Key",
    "Sm2Signature",
    # SM9 Identity-Based Cryptography
    "SM9_MAX_CIPHERTEXT_SIZE",
    "SM9_MAX_ID_SIZE",
    "SM9_MAX_PLAINTEXT_SIZE",
    "SM9_SIGNATURE_SIZE",
    "Sm9EncMasterKey",
    "Sm9SignMasterKey",
    "Sm9Signature",
    # X.509 Certificate Parsing Utilities
    "Validity",
    "gmssl_parse_attr_type_and_value",
    "gmssl_parse_name",
    "gmssl_parse_rdn",
]

