# Required dependencies
You should always use the highest version available that conforms to these dependencies.

|Dependency   |Minimum Version|Maximum Version|Links and Notes
|:------------|:-------------:|:-------------:|:---:
|Boost        |    `1.54.0`   |      N/A      |http://www.boost.org/users/download/#live
|Berkeley DB  |    `5.3.0`    |      N/A      |http://www.oracle.com/technetwork/database/database-technologies/berkeleydb/downloads/index-082944.html
|OpenSSL      |    `1.0.2a`   |    `1.0.2l`   |https://github.com/openssl/openssl/releases/
|Pthreads     |      N/A      |      N/A      |More than likely you already have it, and won't have to download anything.

## Build-time dependencies
Dependency                                    |Notes
:--------------------------------------------:|:---:
CMake                                         |Minimum Version `3.2.3`
Make                                          |Only for Unix-based (Linux & Mac) systems.
C/C++ compiler compatible with CMake          |`GCC >= 4.8` on Linux, `MSVC` on Windows, `Clang` on Mac.


### Alternative downloads for Windows
[Boost binaries for Windows.](https://sourceforge.net/projects/boost/files/boost-binaries/)  
[OpenSSL binaries for Windows.](https://slproweb.com/products/Win32OpenSSL.html)  
[PThreads for Windows](https://sourceware.org/pthreads-win32/)  
Optional: [MinGW, the GNU tools for Windows.](http://mingw.org/)  
