# Bundled GmSSL Libraries

## Overview

Starting from version 2.2.2, `gmssl-python` includes pre-compiled GmSSL dynamic libraries for major platforms, enabling "pip install and go" experience without requiring users to manually install GmSSL.

## Supported Platforms

| Platform | Architecture | Library File | GLIBC | Status |
|----------|-------------|--------------|-------|--------|
| macOS | arm64 + x86_64 | `libgmssl.3.dylib` | N/A | ✅ Included (universal binary) |
| Linux | x86_64 | `libgmssl.so.3.x86_64` | 2.17+ | ✅ Included (manylinux2014) |
| Linux | aarch64 | `libgmssl.so.3.aarch64` | 2.17+ | ✅ Included (manylinux2014) |
| Windows | x86_64 | `gmssl.dll` | N/A | ✅ Included |

### Linux Compatibility

The Linux libraries are built using **manylinux2014** containers, which ensures compatibility with:

- ✅ **Ubuntu**: 14.04 LTS and later (including 22.04 LTS, 24.04 LTS)
- ✅ **Debian**: 8 (Jessie) and later (including 11, 12)
- ✅ **RHEL/CentOS**: 7 and later (including Rocky Linux 8, 9)
- ✅ **Fedora**: All recent versions
- ✅ **Arch Linux**: All versions
- ✅ **Other distributions**: Any with GLIBC 2.17 or later

**Minimum Requirements**:
- GLIBC 2.17 or later (released in 2012)
- Only depends on `libc.so.6` (no other external dependencies)

### macOS Compatibility

The macOS library is a universal binary supporting:
- ✅ **macOS 11.0 (Big Sur)** and later
- ✅ Both **Intel (x86_64)** and **Apple Silicon (arm64)** Macs

## Library Loading Strategy

The library loading follows the "Never break userspace" principle:

```
1. System library (if exists)
   ↓ (if not found or version < 3.1.1)
2. Bundled library (in package)
   ↓ (if not found)
3. Error with clear message
```

### Priority Rationale

**Why system library first?**
- Respects user's choice and existing installations
- Allows users to upgrade GmSSL independently
- Prevents breaking existing deployments
- Enables developers to test against different versions

**Why bundled library second?**
- Provides convenience for new users
- Enables "pip install" to just work
- Reduces installation friction
- Suitable for most use cases

## Building Libraries

### Automated Build (Recommended)

Use the GitHub Actions workflow:

1. Go to **Actions** tab
2. Select **Build GmSSL Libraries**
3. Click **Run workflow**
4. Enter GmSSL version (default: 3.1.1)
5. Wait for PR to be created

The workflow will:
- Build libraries for all platforms in parallel
- Create macOS universal binary (arm64 + x86_64)
- Generate a PR with updated libraries
- Include verification steps

### Manual Build

#### macOS

```bash
# Clone GmSSL
git clone --depth 1 --branch v3.1.1 https://github.com/guanzhi/GmSSL.git
cd GmSSL

# Build for arm64
mkdir build-arm64 && cd build-arm64
cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_OSX_ARCHITECTURES=arm64
make -j$(sysctl -n hw.ncpu)
cp bin/libgmssl.3.dylib ../../GmSSL-Python/src/gmssl/_libs/libgmssl.3.dylib.arm64

# Build for x86_64
cd ..
mkdir build-x86_64 && cd build-x86_64
cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_OSX_ARCHITECTURES=x86_64
make -j$(sysctl -n hw.ncpu)
cp bin/libgmssl.3.dylib ../../GmSSL-Python/src/gmssl/_libs/libgmssl.3.dylib.x86_64

# Create universal binary
cd ../../GmSSL-Python/src/gmssl/_libs
lipo -create libgmssl.3.dylib.arm64 libgmssl.3.dylib.x86_64 \
     -output libgmssl.3.dylib
rm libgmssl.3.dylib.arm64 libgmssl.3.dylib.x86_64

# Verify
file libgmssl.3.dylib
otool -L libgmssl.3.dylib
```

#### Linux x86_64

```bash
# Clone GmSSL
git clone --depth 1 --branch v3.1.1 https://github.com/guanzhi/GmSSL.git
cd GmSSL

# Build
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)

# Copy library
cp bin/libgmssl.so.3 ../../GmSSL-Python/src/gmssl/_libs/libgmssl.so.3.x86_64

# Create symlink (for backward compatibility)
cd ../../GmSSL-Python/src/gmssl/_libs/
ln -sf libgmssl.so.3.x86_64 libgmssl.so.3

# Verify
file libgmssl.so.3.x86_64
ldd libgmssl.so.3.x86_64
```

#### Linux aarch64

```bash
# On aarch64 machine or using QEMU
git clone --depth 1 --branch v3.1.1 https://github.com/guanzhi/GmSSL.git
cd GmSSL

# Build
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)

# Copy library
cp bin/libgmssl.so.3 ../../GmSSL-Python/src/gmssl/_libs/libgmssl.so.3.aarch64

# Verify
file ../../GmSSL-Python/src/gmssl/_libs/libgmssl.so.3.aarch64
ldd ../../GmSSL-Python/src/gmssl/_libs/libgmssl.so.3.aarch64
```

**Using Docker for cross-compilation:**

```bash
# Clone GmSSL
git clone --depth 1 --branch v3.1.1 https://github.com/guanzhi/GmSSL.git

# Build in ARM64 container
docker run --rm --platform linux/arm64 \
  -v $PWD/GmSSL:/workspace \
  -v $PWD/GmSSL-Python/src/gmssl/_libs:/output \
  arm64v8/ubuntu:22.04 \
  bash -c "
    apt-get update && \
    apt-get install -y build-essential cmake file && \
    cd /workspace && \
    mkdir -p build && cd build && \
    cmake .. -DCMAKE_BUILD_TYPE=Release && \
    make -j\$(nproc) && \
    cp bin/libgmssl.so.3 /output/libgmssl.so.3.aarch64 && \
    file /output/libgmssl.so.3.aarch64 && \
    ldd /output/libgmssl.so.3.aarch64
  "
```

#### Windows

```powershell
# Clone GmSSL
git clone --depth 1 --branch v3.1.1 https://github.com/guanzhi/GmSSL.git
cd GmSSL

# Build
mkdir build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -A x64
cmake --build . --config Release

# Copy library
cp bin/Release/gmssl.dll ../../GmSSL-Python/src/gmssl/_libs/

# Verify
dir ..\..\GmSSL-Python\src\gmssl\_libs\gmssl.dll
```

## Verification

After building or updating libraries, verify they work correctly:

### Basic Verification

```bash
# Test library loading
python -c "
import sys
sys.path.insert(0, 'src')
from gmssl._lib import gmssl, _find_gmssl_library
print(f'Loaded from: {_find_gmssl_library()}')
print(f'Version: {gmssl.gmssl_version_num()}')
"

# Run full test suite (library is self-contained)
pytest tests/ -v

# Build wheel and verify library is included
python -m build --wheel
unzip -l dist/gmssl_python-*.whl | grep -E "(\.dylib|\.so|\.dll)"
```

### Compatibility Verification

Compatibility is automatically verified in CI by testing on:
- **Ubuntu 22.04 LTS** (GLIBC 2.35) - Critical LTS version
- **Ubuntu latest** (GLIBC 2.39+) - Latest stable
- **macOS latest** - Both Intel and Apple Silicon
- **Windows latest** - Windows 10/11

If all CI tests pass, the library is compatible with the target platforms.

### Check GLIBC Requirements

```bash
# Check maximum GLIBC version required
objdump -T src/gmssl/_libs/libgmssl.so.3.x86_64 | grep GLIBC | awk '{print $5}' | sort -Vu | tail -1

# Should output: GLIBC_2.17 (or lower for maximum compatibility)

# Check external dependencies (should only depend on libc.so.6)
readelf -d src/gmssl/_libs/libgmssl.so.3.x86_64 | grep NEEDED
```

## License

GmSSL is licensed under Apache License 2.0, same as this project.

**Redistribution Compliance:**
- ✅ Apache-2.0 allows redistribution of binaries
- ✅ Both projects use the same license
- ✅ Copyright notices are preserved
- ✅ Users are informed via README and this document

**GmSSL Information:**
- **Project**: https://github.com/guanzhi/GmSSL
- **Version**: 3.1.1
- **License**: Apache License 2.0
- **Copyright**: Copyright 2014-2023 The GmSSL Project

## Troubleshooting

### Library not found after installation

```python
# Check if library is in the package
import gmssl
import os
lib_dir = os.path.join(os.path.dirname(gmssl.__file__), '_libs')
print(f'Library directory: {lib_dir}')
print(f'Contents: {os.listdir(lib_dir) if os.path.exists(lib_dir) else "NOT FOUND"}')
```

### System library used instead of bundled

This is expected behavior! System library has priority.

To force bundled library:
```bash
# Temporarily rename system library
sudo mv /usr/local/lib/libgmssl.so.3 /usr/local/lib/libgmssl.so.3.bak

# Or uninstall system GmSSL
sudo make uninstall  # in GmSSL build directory
```

### Version mismatch

```python
# Check which library is loaded
from gmssl._lib import gmssl, _find_gmssl_library
print(f'Library path: {_find_gmssl_library()}')
print(f'Version: {gmssl.gmssl_version_num()}')
print(f'Expected: >= 30101')
```

### Build failures

**macOS universal binary fails:**
- Fallback: Use arm64-only library
- Or build separately and use `lipo` manually

**Linux missing dependencies:**
```bash
sudo apt-get install build-essential cmake
```

**Windows MSVC not found:**
- Install Visual Studio 2019 or later
- Or use Visual Studio Build Tools

## Architecture Detection

The library loading logic automatically detects the system architecture on Linux:

```python
import platform

machine = platform.machine().lower()
# Returns: 'x86_64', 'amd64', 'aarch64', 'arm64', etc.

# Library selection:
# - aarch64/arm64 → libgmssl.so.3.aarch64
# - x86_64/amd64  → libgmssl.so.3.x86_64
# - Fallback      → libgmssl.so.3 (symlink)
```

This ensures the correct library is loaded on multi-architecture systems.

## Future Improvements

- [x] Add ARM64 Linux support (aarch64)
- [ ] Add ARM Windows support
- [ ] Automated version updates via Dependabot
- [ ] Binary size optimization (strip symbols)
- [ ] Platform-specific wheels (manylinux, etc.)
