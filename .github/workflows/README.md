# GitHub Actions Workflows

## Build GmSSL Libraries

### Purpose

The `build-gmssl-libs.yml` workflow builds GmSSL dynamic libraries for multiple platforms and creates a PR to update the bundled libraries in `src/gmssl/_libs/`.

### Supported Platforms

- **Linux**: x86_64 (`libgmssl.so.3`)
- **macOS**: Universal binary arm64 + x86_64 (`libgmssl.3.dylib`)
- **Windows**: x86_64 (`gmssl.dll`)

### How to Use

1. Go to **Actions** tab in GitHub
2. Select **Build GmSSL Libraries** workflow
3. Click **Run workflow**
4. Enter parameters:
   - **GmSSL version**: e.g., `3.1.1` (default)
   - **GmSSL repository**: e.g., `https://github.com/guanzhi/GmSSL.git` (default)
5. Click **Run workflow** button

### What Happens

1. **Build Stage**: Compiles GmSSL for each platform in parallel
   - Linux x86_64: Ubuntu latest with GCC
   - Linux aarch64: Ubuntu with QEMU (ARM64 emulation)
   - macOS arm64: macOS latest (M1/M2)
   - macOS x86_64: macOS 13 (Intel)
   - Windows x86_64: Windows latest with MSVC

2. **Artifact Stage**: Uploads compiled libraries as artifacts
   - Retention: 7 days
   - Can be downloaded manually if needed

3. **Test Stage**: Automatically tests libraries on multiple platforms
   - **Linux**: Tests with Python 3.8, 3.9, 3.10, 3.11, 3.12
   - **macOS**: Tests with Python 3.12 (universal binary)
   - **Windows**: Tests with Python 3.12
   - Runs full test suite (`pytest tests/ -v`)
   - Verifies library loading and version info
   - **Fail-fast disabled**: All combinations tested even if one fails

4. **PR Stage**: Creates a pull request with updated libraries (only if tests pass)
   - Branch: `update-gmssl-libs-{version}`
   - Includes all platform libraries
   - macOS: Creates universal binary (arm64 + x86_64)
   - **All tests must pass** before PR is created

### Testing the PR

**Automated Testing**: The workflow automatically tests all libraries before creating the PR. You can review test results in the Actions tab.

**Manual Testing** (optional): If you want to test locally:

```bash
# Clone the PR branch
git fetch origin update-gmssl-libs-{version}
git checkout update-gmssl-libs-{version}

# Run tests (library is self-contained, no environment setup needed)
pytest tests/ -v

# Build wheel and verify library is included
python -m build --wheel
unzip -l dist/gmssl_python-*.whl | grep -E "(\.dylib|\.so|\.dll)"
```

**Test Coverage**:
- ✅ Linux x86_64: Python 3.8, 3.9, 3.10, 3.11, 3.12
- ✅ macOS universal: Python 3.12
- ✅ Windows x86_64: Python 3.12
- ✅ All 19 test cases from `tests/test_gmssl.py`

### Manual Library Update

If you need to update libraries manually:

1. Build GmSSL on your platform:
   ```bash
   git clone https://github.com/guanzhi/GmSSL.git
   cd GmSSL
   mkdir build && cd build
   cmake .. -DCMAKE_BUILD_TYPE=Release
   make -j$(nproc)
   ```

2. Copy library to package:
   ```bash
   # Linux
   cp bin/libgmssl.so.3 ../GmSSL-Python/src/gmssl/_libs/
   
   # macOS
   cp bin/libgmssl.3.dylib ../GmSSL-Python/src/gmssl/_libs/
   
   # Windows
   cp bin/Release/gmssl.dll ../GmSSL-Python/src/gmssl/_libs/
   ```

3. Verify and commit:
   ```bash
   cd ../GmSSL-Python
   git add src/gmssl/_libs/
   git commit -m "chore: update bundled GmSSL library for {platform}"
   ```

### Troubleshooting

**Q: Workflow fails on Windows build**
- Check if GmSSL CMake configuration supports Windows
- Verify MSVC toolchain is properly set up
- Check GmSSL version compatibility

**Q: macOS universal binary creation fails**
- Fallback: Uses arm64 library only
- Can manually create universal binary with `lipo` command

**Q: Library dependencies missing**
- GmSSL should only depend on system libraries
- Check with `ldd` (Linux), `otool -L` (macOS), or `dumpbin /dependents` (Windows)

**Q: Tests fail on specific platform**
- Check the Actions tab for detailed test output
- Common issues:
  - Library not found: Verify artifact download step
  - Import errors: Check Python version compatibility
  - Test failures: May indicate library build issues
- PR will not be created if any tests fail

**Q: Want to skip tests and create PR anyway**
- Not recommended, but you can:
  - Manually download artifacts from the workflow run
  - Create PR manually following the steps in "Manual Library Update"

### License

GmSSL is licensed under Apache-2.0, same as this project.
Redistribution is permitted under the terms of the Apache License 2.0.

