Required dependencies
======
You should always use the highest version available that conforms to these dependencies.

|Dependency |Version             |Names on Ubuntu          |Names on Homebrew
|:----------|:------------------:|:-----------------------:|:------:
|Boost      |min. `1.54`         |`libboost-all-dev`       |`boost`
|Berkeley DB|min. `5.0` max `6.1`|`libdb++-dev` `libdb-dev`|`berkeley-db`
|OpenSSL    |min/max `1.0.2`     |`openssl`                |`openssl`

Build-time dependencies
---
|Dependency        |Linux        |OSX               |Windows
|:----------------:|:-----------:|:----------------:|:---:
|`CMake`           |✔️            |✔️                 |✔️
|`Make`            |✔️            |✔️                 |❌
|`NMake` (optional)|❌            |❌                 |✔️
|C++ compiler      |`GCC` `Clang`|`GCC` `AppleClang`|`MSVC`

Windows downloads
---
Visual Studio comes with the `MSVC` compiler and C++ libraries if you select "Desktop Development with C++" when installing.  

[Berkeley DB](http://www.oracle.com/technetwork/database/database-technologies/berkeleydb/downloads/index-082944.html) -- Copy the download link for your desired version, and remove `otn/` from the link.  
[Boost binaries](https://sourceforge.net/projects/boost/files/boost-binaries/)  
[OpenSSL binaries](https://slproweb.com/products/Win32OpenSSL.html) -- Get the full developer version, not light.  
[Visual Studio](https://www.visualstudio.com)  
[Cmake](https://cmake.org/download/)   

OSX downloads
---
[Homebrew](https://brew.sh/) -- Make sure to follow the setup guide on their site.  

Homebrew currently gets a Berkeley DB version too high, so use `brew install https://raw.githubusercontent.com/Homebrew/homebrew-core/1e62c645b2fc2d82042d9f7c364c6a246f2e11ed/Formula/berkeley-db.rb`
