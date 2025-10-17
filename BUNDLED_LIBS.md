# Bundled GmSSL Libraries

## Overview

Starting from version 2.2.2, `gmssl-python` includes pre-compiled GmSSL dynamic libraries for major platforms, enabling "pip install and go" experience without requiring users to manually install GmSSL.

## Supported Platforms

| Platform | Architecture | Library File | Status |
|----------|-------------|--------------|--------|
| macOS | arm64 | `libgmssl.3.dylib` | ✅ Included |
| macOS | x86_64 | `libgmssl.3.dylib` | ⏳ Pending (will be universal binary) |
| Linux | x86_64 | `libgmssl.so.3` | ⏳ Pending |
| Windows | x86_64 | `gmssl.dll` | ⏳ Pending |

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

#### Linux

```bash
# Clone GmSSL
git clone --depth 1 --branch v3.1.1 https://github.com/guanzhi/GmSSL.git
cd GmSSL

# Build
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)

# Copy library
cp bin/libgmssl.so.3 ../../GmSSL-Python/src/gmssl/_libs/

# Verify
file ../GmSSL-Python/src/gmssl/_libs/libgmssl.so.3
ldd ../GmSSL-Python/src/gmssl/_libs/libgmssl.so.3
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

```bash
# Test library loading
python -c "
import sys
sys.path.insert(0, 'src')
from gmssl._lib import gmssl, _find_gmssl_library
print(f'Loaded from: {_find_gmssl_library()}')
print(f'Version: {gmssl.gmssl_version_num()}')
"

# Run full test suite
source .venv/bin/activate
./scripts/run_tests.sh -v

# Build wheel and verify library is included
python -m build --wheel
unzip -l dist/gmssl_python-*.whl | grep -E "(\.dylib|\.so|\.dll)"
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

## Future Improvements

- [ ] Add ARM64 Linux support
- [ ] Add ARM Windows support
- [ ] Automated version updates via Dependabot
- [ ] Binary size optimization (strip symbols)
- [ ] Platform-specific wheels (manylinux, etc.)

