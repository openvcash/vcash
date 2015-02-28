vanillacoin
===========

A decentralized currency for the internet.

Dependencies:

boost 1.53.0
db-4.8.30
openssl

```
Extract boost to ./deps

Run ./deps/boost/bootstrap.sh or ./deps/boost/bootstrap.bat

Copy bjam or bjam.exe if needed.

./bjam or bjam.exe link=static --with-system toolset=clang cxxflags="-std=c++11 -stdlib=libc++" release

Extract db and openssl to ./deps/db and ./deps/openssl on linux. On Mac OS X and Windows extract them to ./deps/platform/osx and ./deps/platform/windows respectively.

Compile db and openssl.

For Linux:

bjam toolset=gcc cxxflags=-std=gnu++0x release

cd test

bjam toolset=gcc cxxflags=-std=gnu++0x release

For Mac OS X:

bjam toolset=clang cxxflags="-std=c++11 -stdlib=libc++" linkflags="-stdlib=libc++" release

cd test

bjam toolset=clang cxxflags="-std=c++11 -stdlib=libc++" linkflags="-stdlib=libc++" release

For Windows:

bjam.exe toolset=msvc link=static runtime-link=static release

cd test

bjam.exe toolset=msvc link=static runtime-link=static release
```

Thank you for your support.
