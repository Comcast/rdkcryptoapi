# RDKCryptoAPI

## Summary

RDKCryptoAPI contains cryptographic APIs used in the RDK Software Stack and an OpenSSL reference implementation.

## Building

### Generate Build Files

To build RDKCryptoAPI, first run cmake to generate build files.

The build assumes that the following packages have already been installed:
YAJL - include -DYAJL_ROOT=<directory> if not found
OPENSSL - include -DOPENSSL_ROOT_DIR=<directory> if not found
Add -DCMAKE_INSTALL_PREFIX=<directory> to install to a non-standard install directory.

```
cmake -S . -B cmake-build
```

### Build

To build RDKCryptoAPI, run a cmake build

```
cmake --build cmake-build
```

This creates a library, libsec_api.(so/dll/dylib) containing the RDKCryptoAPI code (the extension .so/.dll/.dylib
created depends on which platform you are building on). It also creates a test application, sec_api_test, to
test the library.

Run unit test suite

```
cmake-build/sec_api_test
```

### Install

To install RDKCryptoAPI, run a cmake install

```
cmake --install cmake-build
```

This copies the include files, the library, libsec_api.(so/dll/dylib) containing the RDKCryptoAPI reference code (the
extension .so/.dll/.dylib created depends on which platform you are building on), and the test application,
sec_api_test, to their appropriate locations on the system.

## Dependencies

RDKCryptoAPI depends on OpenSSL 1.0.2 or 1.1.1 and YAJL version 1 or 2.
