General Build Info
======
# WARNING
**Pre-existing wallet data is not backwards compatible with version v5 of BerkeleyDB if it was originally built with v6.**

This will require you to delete your [Vcash data folder](COMMON_ISSUES.md), and recreate your wallet.

You can import your private keys or wallet seed into the new wallet, but if you do not have these then you will not be able to recover the wallet.

Build flags
---
Use the build flags between `cmake` and `CMakeLists.txt` to trigger certain options, or to choose where to install things.

**Example:** `cmake -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_INSTALL_BINDIR=bin -DCMAKE_INSTALL_LIBDIR=lib/vcash CMakeLists.txt`


Flags                   |Required|Linux/Mac Rec. Setting|Windows Rec. Setting
:-----------------------|:------:|:--------------------:|:---:
`-DCMAKE_INSTALL_PREFIX`|  Yes   |       `/usr`         |`C:\`
`-DCMAKE_INSTALL_BINDIR`|  Yes   |        `bin`         |`"Program Files\Vcash"`
`-DCMAKE_INSTALL_LIBDIR`|  Yes   |     `lib/vcash`      |`"Program Files\Vcash"`
`-DOPENSSL_COMPAT`      |  No    |  `ON` only if needed |Do not use on Windows

OpenSSL problems - Linux/Mac (Unix)
---
If you are having issues with CMake finding OpenSSL `1.0.2`, say, because you might have version `1.1.0` (or higher) already installed, then try building with the `-DOPENSSL_COMPAT=ON` flag (UNIX-only). If that doesn't work, then create the following symlinks:

1. `ln -s /usr/include/openssl-1.0/openssl/bn.h /location/of/include/openssl-1.0/bn.h` Make sure that you are linking to the folder with `bn.h` in it.
2. `ln -s /usr/lib/libcrypto.so.1.0.0 /location/of/lib/libcrypto.so.1.0.0` Make sure you are linking to the location of `libcrypto.so.1.0.0` and **not** the newer OpenSSL file, normally just named `libcrypto`
3. `ln -s /usr/lib/libssl.so.1.0.0 /location/of/lib/libssl.so.1.0.0` Make sure you are linking to the location of `libssl.so.1.0.0` and **not** the newer OpenSSL file, normally just named `libssl.so`

Afterwords, use the `-DOPENSSL_COMPAT=ON` build flag when building with cmake.

Build Errors
---
Problem|Solution
:---:|:---:
`c++: internal compiler error: Killed (program cc1plus)`|You ran out of RAM during building. Increase your swap partition to account for this, or add more RAM to your system. 1GB minimum, 2GB if you are running an incentive node.
