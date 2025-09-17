---
sidebar_position: 2
---

# Building nDPI

This guide covers how to build nDPI from source using different build systems.

## Prerequisites

Before building nDPI, ensure you have the following installed:

### Required Dependencies
- **GCC/Clang**: C compiler with C99 support
- **Make**: GNU Make or compatible
- **autotools**: autoconf, automake, libtool
- **pkg-config**: For dependency management

### Optional Dependencies
- **libpcap**: For packet capture support (development packages)
- **libmaxminddb**: For GeoIP support
- **libgcrypt**: For cryptographic functions
- **libcurl**: For HTTP-based features
- **json-c**: For JSON serialization support

## Installation Commands

### Ubuntu/Debian
```bash
sudo apt update
sudo apt install build-essential autoconf automake libtool pkg-config
sudo apt install libpcap-dev libjson-c-dev libmaxminddb-dev
```

### CentOS/RHEL/Fedora
```bash
# CentOS/RHEL
sudo yum install gcc make autoconf automake libtool pkgconfig
sudo yum install libpcap-devel json-c-devel libmaxminddb-devel

# Fedora
sudo dnf install gcc make autoconf automake libtool pkgconfig
sudo dnf install libpcap-devel json-c-devel libmaxminddb-devel
```

### macOS
```bash
# Using Homebrew
brew install autoconf automake libtool pkg-config
brew install libpcap json-c libmaxminddb
```

## Building with Autotools (Traditional)

### Basic Build
```bash
# Clone the repository
git clone https://github.com/ntop/nDPI.git
cd nDPI

# Generate configure script
./autogen.sh

# Configure build
./configure

# Compile
make

# Install (optional)
sudo make install
```

### Configure Options

nDPI supports various configure options:

```bash
# Library only (no examples or tests)
./configure --with-only-libndpi

# Enable/disable shared library
./configure --enable-shared=yes --enable-static=no

# Custom installation prefix
./configure --prefix=/usr/local

# Enable debug build
./configure --enable-debug-build

# Enable fuzzing targets
./configure --enable-fuzztargets

# With external libgcrypt
./configure --with-local-libgcrypt

# With PCRE2 support
./configure --with-pcre2

# With MaxMind GeoIP support
./configure --with-maxminddb
```

### Complete Example
```bash
./configure \
  --prefix=/usr/local \
  --enable-shared=yes \
  --enable-static=yes \
  --with-pcre2 \
  --with-maxminddb \
  --with-local-libgcrypt
make -j$(nproc)
sudo make install
```

## Building with Bazel

We provide Bazel support using foreign_cc rules for modern build environments.

### Prerequisites
- **Bazel**: Version 6.0 or later
- **Standard build tools**: GCC, make, autotools

### Build Commands
```bash
# Build the library
bazel build //:libndpi

# Build all targets
bazel build //...

# Build and run tests
bazel test //...
```

### Using in Other Bazel Projects
Add to your `WORKSPACE` file:

```starlark
local_repository(
    name = "ndpi",
    path = "/path/to/ndpi",
)
```

Then in your `BUILD.bazel`:

```starlark
cc_binary(
    name = "my_app",
    srcs = ["main.c"],
    deps = ["@ndpi//:libndpi"],
)
```

## Building with CMake

For projects that prefer CMake, you can create a basic CMakeLists.txt:

```cmake
cmake_minimum_required(VERSION 3.10)
project(ndpi)

# Find dependencies
find_package(PkgConfig REQUIRED)
find_package(Threads REQUIRED)

# Add custom target to build nDPI
add_custom_target(ndpi_autotools
    COMMAND ./autogen.sh
    COMMAND ./configure --with-only-libndpi
    COMMAND make -j${CMAKE_BUILD_PARALLEL_LEVEL}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

# Create imported library
add_library(ndpi STATIC IMPORTED)
add_dependencies(ndpi ndpi_autotools)

set_target_properties(ndpi PROPERTIES
    IMPORTED_LOCATION ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/libndpi.a
    INTERFACE_INCLUDE_DIRECTORIES ${CMAKE_CURRENT_SOURCE_DIR}/src/include
)
```

## Cross-Compilation

### ARM/Embedded Systems
```bash
# Set cross-compiler
export CC=arm-linux-gnueabihf-gcc
export AR=arm-linux-gnueabihf-ar
export RANLIB=arm-linux-gnueabihf-ranlib

# Configure for cross-compilation
./configure --host=arm-linux-gnueabihf --with-only-libndpi
make
```

### Android
```bash
# Set Android NDK paths
export ANDROID_NDK=/path/to/android-ndk
export TOOLCHAIN=$ANDROID_NDK/toolchains/llvm/prebuilt/linux-x86_64

# Configure for Android
./configure \
  --host=aarch64-linux-android \
  --with-only-libndpi \
  CC=$TOOLCHAIN/bin/aarch64-linux-android21-clang
make
```

## Verification

After building, verify the installation:

```bash
# Check library
file src/lib/libndpi.a
ldd src/lib/libndpi.so  # if shared library built

# Test with example
cd example
make
./ndpiReader -i en0  # or your network interface
```

## Build Options Reference

| Option | Description | Default |
|--------|-------------|---------|
| `--with-only-libndpi` | Build library only | No |
| `--enable-shared` | Build shared library | Yes |
| `--enable-static` | Build static library | Yes |
| `--enable-debug-build` | Debug build with symbols | No |
| `--with-pcre2` | Enable PCRE2 support | No |
| `--with-maxminddb` | Enable GeoIP support | No |
| `--with-local-libgcrypt` | Use system libgcrypt | No |
| `--enable-fuzztargets` | Build fuzz targets | No |

## Troubleshooting

### Common Issues

**autogen.sh fails**:
```bash
# Install missing autotools
sudo apt install autoconf automake libtool
```

**Configure fails to find dependencies**:
```bash
# Install development packages
sudo apt install libpcap-dev libjson-c-dev
```

**Compilation errors on older systems**:
```bash
# Use older compiler flags
./configure CFLAGS="-std=c99 -O2"
```

**Permission denied during install**:
```bash
# Use sudo or custom prefix
./configure --prefix=$HOME/local
make install
```

## Next Steps

Once you've successfully built nDPI, you can:

- [Learn basic integration](./basic-integration)
- [Explore the API reference](./api-reference)
- [Check out examples](./examples)
- [Understand flow management](./flows)