General Build Info
======
# WARNING
**Pre-existing wallet data is not backwards compatible with version v5 of Berkeley DB if it was originally built with v6.**

If you build with v5 and have old wallet data that was built with v6, you will need to delete your [Vcash data folder](COMMON_ISSUES.md), and recreate your wallet.

You can import your private keys or recover from your wallet seed, but if you do not have these then you will not be able to recover the wallet.

Build flags
---
Use the various build flags when initiating `cmake` to trigger certain options, or to choose where to install things.   
**Example:** `cmake -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_INSTALL_BINDIR=bin -DCMAKE_INSTALL_LIBDIR=lib/vcash`  

Most of the flags shouldn't be used unless you are having problems, with the exception of the CMAKE_INSTALL_X flags, as those can be safely used without potentially messing up the build process.  

If your path contains spaces, or any other weirdness, put double quotes around it. **Example:** `cmake -DBERKELEYDB_INCLUDES_PATH="Program Files (x86)"`

Note that, depending on the location, install prefixes might require doing `sudo make install` instead of `make install` (Unix only).
None of these are required for the build process, and should only be used if you understand what they do.

Flags                          |Unix Example Setting|Windows Example Setting
:------------------------------|:------------------:|:---:
`-DCMAKE_INSTALL_PREFIX`       |`/usr`              |`C:/`
`-DCMAKE_INSTALL_BINDIR`       |`bin`               |`"Program Files/Vcash"`
`-DCMAKE_INSTALL_LIBDIR`       |`lib/vcash`         |`"Program Files/Vcash"`
`-DBERKELEYDB_INCLUDES_PATH`   |`/usr/include/db`   |`"C:/Program Files/db/include"`
`-DBERKELEYDB_LIB_PATH`        |`/usr/lib`          |`"C:/Program Files/db/lib"`
`-DBERKELEYDB_LIB_NAME`        |`libdb_cxx.so`      |`db_cxx.lib`

**If you use `-DBERKELEYDB_LIB_NAME` or `-DBERKELEYDB_LIB_SUFFIX` then they must both be used. You cannot use them independently from eachother.**

OpenSSL problems
---
If CMake is not finding the correct version of OpenSSL, perhaps because you have a newer version installed along side your older OpenSSL 1.0.2, then you need to pass their paths with cmake flags.  

**Example for Arch Linux:** `cmake -DOPENSSL_INCLUDE_DIR=/usr/include/openssl-1.0 -DOPENSSL_SSL_LIBRARY=/usr/lib/libssl.so.1.0.0 -DOPENSSL_CRYPTO_LIBRARY=/usr/lib/libcrypto.so.1.0.0`  

Make sure to pass the correct paths, as it expects to see `openssl/HEADERFILESHERE` in the includes path.  

Build Errors
---
Problem|Solution
:---:|:---:
`c++: internal compiler error: Killed (program cc1plus)`|You ran out of RAM during building. Increase your swap partition to account for this, or add more RAM to your system. 1GB minimum to build, [2GB if you are running an incentive node.](https://docs.vcash.info/technologies/node-incentives/)
