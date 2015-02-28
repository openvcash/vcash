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

cd ./deps/boost

For Linux:

./bjam toolset=gcc cxxflags=-std=gnu++0x --with-system  release

For Mac OS X:

./bjam link=static --with-system toolset=clang cxxflags="-std=c++11 -stdlib=libc++" release install

For Windows:

bjam.exe link=static runtime-link=static --with-system toolset=msvc release install

Extract db and openssl to ./deps/db and ./deps/openssl on linux. On Mac OS X and Windows extract them to ./deps/platform/osx and ./deps/platform/windows respectively.

Compile db and openssl.

cd ./

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
