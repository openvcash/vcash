# Windows build process with Visual Studio or Bjam.
## Reminder !
Don't forget to backup your data before any upgrade / test session.
Backup your wallet.dat file with the "backupwallet" RPC method.
Backup your private keys with the "dumpwallet" RPC method.
For a deterministic wallet, backup your seed with the "dumpwalletseed" RPC method.
The Vcash data folder is located at C:\Users\\<your_username>\AppData\Roaming\Vcash\
(Don't forget to close the daemon before making a copy of the entire data folder).

## Visual Studio
Tested on Windows 8.1 x64 with MSVC12 (Visual Studio 2013)
#### Req.
- Visual Studio 2013
- Boost 1.57: https://sourceforge.net/projects/boost/files/boost/1.57.0/
- Berkeley DB 6.1.29: http://download.oracle.com/berkeley-db/db-6.1.29.NC.zip
- OpenSSL x86 & x64:https://slproweb.com/products/Win32OpenSSL.html
- Vcash sources: https://github.com/xCoreDev/vcash/archive/master.zip

#### Preparation
##### Vcash
- Unzip master.zip (Example: extract the vcash-master folder from the archive to C:\\)

##### Boost
- Unzip boost_1_57_0.zip to the .\deps\ folder (Example: C:\vcash-master\deps\boost_1_57_0\\)
- Rename the .\deps\boost_1_57_0\ folder to .\deps\boost\ (Example: C:\vcash-master\deps\boost\\)

##### Berkeley DB
- Unzip db-6.1.29.NC.zip to the .\deps\ folder (Example: C:\vcash-master\deps\db-6.1.29.NC\\
- Rename the .\deps\db-6.1.29.NC\ folder to .\deps\db\ (Example: C:\vcash-master\deps\db\\)

##### OpenSSL
- Download last Win32 OpenSSL v1.0.1* & Win64 OpenSSL v1.0.1* (not the light releases)
- Install Win32OpenSSL to .\deps\openssl\OpenSSL-Win32\ (Example: C:\vcash-master\deps\openssl\OpenSSL-Win32\\)
- Install Win64OpenSSL to .\deps\openssl\OpenSSL-Win64\ (Example: C:\vcash-master\deps\openssl\OpenSSL-Win64\\)

#### Build dependencies
##### Boost
To build the static boost_system libs for x86 & x64, open a command prompt, then:
```
call "%VS120COMNTOOLS%..\..\VC\vcvarsall.bat" x86
cd C:\vcash-master\deps\boost\
call bootstrap.bat
b2 -j3 toolset=msvc-12.0 address-model=64 architecture=x86 link=static threading=multi runtime-link=static --with-system --stagedir=stage/x64 
b2 -j3 toolset=msvc-12.0 address-model=32 architecture=x86 link=static threading=multi runtime-link=static --with-system --stagedir=stage/win32
```

##### Berkeley DB
- Open Visual Studio 2013
- Open the .\deps\db\build_windows\Berkeley_DB_vs2010.sln solution
- Select the "Static Release" configuration / Win32 platform > Right Click on "db" in the Solution Explorer > Build.
- Select the "Static Release" configuration / x64 platform > Right Click on "db" in the Solution Explorer > Build.

#### Build Vcash daemon
- Open Visual Studio 2013
- Open the .\platforms\windows\Vcash.sln solution
- Select desired configuration / platform and Build the solution to get a fresh vcashd.exe
