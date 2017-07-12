# Build flags
Use these between `cmake` and `CMakeLists.txt` to trigger certain options, or to choose where to install things.

**Example:** `cmake -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_INSTALL_BINDIR=bin -DCMAKE_INSTALL_LIBDIRlib/vcash CMakeLists.txt`


Flags                   |Required|Notes
:-----------------------|:------:|:---:
`-DCMAKE_INSTALL_PREFIX`|  Yes   |On Linux, recommended to use `/usr`
`-DCMAKE_INSTALL_BINDIR`|  Yes   |On Linux, recommended to use `bin`
`-DCMAKE_INSTALL_LIBDIR`|  Yes   |On Linux, recommended to use `lib/vcash`
`-DOPENSSL_COMPAT`      |  No    |[Workaround for OpenSSL](docs/build-problems.md)
