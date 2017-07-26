Required dependencies
======
You should always use the highest version available that conforms to these dependencies.

|Dependency |Version         |Name on Ubuntu  |Links and Notes
|:----------|:--------------:|:--------------:|:---:
|Boost      |minimum `1.54.0`|`boost-defaults`|http://www.boost.org/users/download/#live
|Berkeley DB|minimum `6.0.0` |`db-defaults`   |http://www.oracle.com/technetwork/database/database-technologies/berkeleydb/downloads/index-082944.html Copy the download link and remove `otn/` from the link.
|OpenSSL    |exact `1.0.2`   |`openssl`       |https://github.com/openssl/openssl/releases/
|Threads    |N/A             |`libc++`        |It should come with your systems C/C++ libraries.

Build-time dependencies
---
Dependency                          |Notes
:----------------------------------:|:---:
CMake                               |Minimum Version `3.1.3`
Make                                |Linux & Mac only -- alternatively `NMake` on Windows.
C/C++ compiler compatible with CMake|`GCC >= 4.8` on Linux, `MSVC` on Windows, `Clang` on Mac.

Windows downloads
---
Visual Studio comes with the `MSVC` compiler and C++ libraries if you select "Desktop Development with C++" when installing.     

[Boost binaries](https://sourceforge.net/projects/boost/files/boost-binaries/)  
[OpenSSL binaries](https://slproweb.com/products/Win32OpenSSL.html) -- Get the full developer version, not light.  
[Visual Studio Community](https://www.visualstudio.com)  
[Cmake](https://cmake.org/download/)   

Mac downloads
---
[Homebrew](https://brew.sh/), the macOS package manager -- Make sure to follow the setup guide on their site.
