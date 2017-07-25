General Build Info
======
# WARNING
**Pre-existing wallet data is not backwards compatible with version v5 of Berkeley DB if it was originally built with v6.**

If you build with v5 and have old wallet data that was built with v6, you will need to delete your [Vcash data folder](COMMON_ISSUES.md), and recreate your wallet.

You can import your private keys or recover from your wallet seed, but if you do not have these then you will not be able to recover the wallet.

If you are sure you want to build with Berkeley DB v5, and you understand the risks, then use the build flag listed below called `WITH_INCOMPATIBLE_BDB`

Build flags
---
Use the various build flags when initiating `cmake` to trigger certain options, or to choose where to install things. A list of some of them [can be found here.](https://cmake.org/Wiki/CMake_Useful_Variables)

Please note that none of these are required for the build process, and should only be used if you understand what they do.

Custom Flags                   |Unix Example Setting|Windows Example Setting
:------------------------------|:------------------:|:---:
`-DBERKELEYDB_INCLUDES_PATH`   |`/usr/include/db`   |`C:/Program Files/Oracle/Berkeley DB/include`
`-DBERKELEYDB_LIB_PATH`        |`/usr/lib`          |`C:/Program Files/Oracle/Berkeley DB/lib`
`-DBERKELEYDB_LIB_NAME`        |`libdb_cxx.so`      |`libdb62.lib`
`-DWITH_INCOMPATIBLE_BDB`      |`ON`                |`ON`

If you have trouble getting CMake to find [OpenSSL](https://cmake.org/cmake/help/latest/module/FindOpenSSL.html), [Boost](https://cmake.org/cmake/help/latest/module/FindBoost.html), or [Threads](https://cmake.org/cmake/help/latest/module/FindThreads.html) dependencies, try setting their various path flags.

OpenSSL not found
---
If CMake is not finding the correct version of OpenSSL, perhaps because you have a newer version installed along side your older OpenSSL 1.0.2, then you need to pass their paths with cmake flags.  

**Example for Arch Linux:** `cmake -DOPENSSL_INCLUDE_DIR=/usr/include/openssl-1.0 -DOPENSSL_SSL_LIBRARY=/usr/lib/libssl.so.1.0.0 -DOPENSSL_CRYPTO_LIBRARY=/usr/lib/libcrypto.so.1.0.0`  

Make sure to pass the correct paths, as it expects to see `openssl/HEADERFILESHERE` in the includes path.  

Build Errors
---
Problem|Solution
:---:|:---:
`c++: internal compiler error: Killed (program cc1plus)`|You ran out of RAM during building. Increase your swap partition or add more RAM to your system -- 1GB minimum needed.
