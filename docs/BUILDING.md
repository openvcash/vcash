# General Build Info

## Build flags
Use these between `cmake` and `CMakeLists.txt` to trigger certain options, or to choose where to install things.

**Example:** `cmake -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_INSTALL_BINDIR=bin -DCMAKE_INSTALL_LIBDIR=lib/vcash CMakeLists.txt`


Flags                   |Required|Linux Rec. Setting|Windows Rec. Setting
:-----------------------|:------:|:--------------------:|---:
`-DCMAKE_INSTALL_PREFIX`|  Yes   |`/usr`                |`C:\`
`-DCMAKE_INSTALL_BINDIR`|  Yes   |`bin`                 |`"Program Files\Vcash"`
`-DCMAKE_INSTALL_LIBDIR`|  Yes   |`lib/vcash`           |`"Program Files\Vcash"`
`-DOPENSSL_COMPAT`      |  No    |`ON` if needed        |N/A


## OpenSSL problems - Linux/Mac (Unix)
If you are having issues with CMake finding OpenSSL `1.0`, say, because you might have version `1.1` (or higher) already installed, then create the following symlinks:

1. `ln -s /usr/include/openssl-1.0/openssl/bn.h /location/of/include/openssl-1.0/bn.h` Make sure that you are linking to the folder with `bn.h` in it.
2. `ln -s /usr/lib/libcrypto.so.1.0.0 /location/of/lib/libcrypto.so.1.0.0` Make sure you are linking to the location of `libcrypto.so.1.0.0` and **not** the newer OpenSSL file, normally just named `libcrypto`
3. `ln -s /usr/lib/libssl.so.1.0.0 /location/of/lib/libssl.so.1.0.0` Make sure you are linking to the location of `libssl.so.1.0.0` and **not** the newer OpenSSL file, normally just named `libssl.so`

Afterwords, when you go to use cmake to build from source, use the `-DOPENSSL_COMPAT=ON` build flag.
