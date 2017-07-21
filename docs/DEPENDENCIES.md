Required dependencies
======
You should always use the highest version available that conforms to these dependencies.

|Dependency   |Version         |Name on Ubuntu  |Links and Notes
|:------------|:--------------:|:--------------:|:--------------:|:---:
|Boost        |minimum `1.54.0`|`boost-defaults`|http://www.boost.org/users/download/#live
|Berkeley DB  |minimum `6.0.0` |`db-defaults`   |http://www.oracle.com/technetwork/database/database-technologies/berkeleydb/downloads/index-082944.html To download without an account, copy the package download link and remove `otn/` from the link.
|OpenSSL      |exact `1.0.2`   |`openssl`       |https://github.com/openssl/openssl/releases/
|Pthreads     |N/A             |`libc++`        |It should come with your systems C/C++ libraries.

Build-time dependencies
---
Dependency                                    |Notes
:--------------------------------------------:|:---:
CMake                                         |Minimum Version `3.1.3`
Make                                          |`Make` for Linux & Mac, `NMake` for Windows
C/C++ compiler compatible with CMake          |`GCC >= 4.8` on Linux, `MSVC` on Windows, `Clang` on Mac.

Alternative downloads for Windows
---
[Boost binaries for Windows.](https://sourceforge.net/projects/boost/files/boost-binaries/)  
[OpenSSL binaries for Windows.](https://slproweb.com/products/Win32OpenSSL.html)  
[Visual C++ (MSVC and NMake included) for Windows](https://blogs.msdn.microsoft.com/vcblog/2017/03/07/msvc-the-best-choice-for-windows/)  
Optional: [MinGW-w64, the GNU tools for Windows.](http://mingw-w64.org)   
Optional: [Pkg-Config to help the CMake find modules work better](https://www.freedesktop.org/wiki/Software/pkg-config/)
