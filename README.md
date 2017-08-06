# WARNING: DO NOT USE THIS BRANCH IN PRODUCTION!    
# Vcash
> A decentralized currency for the internet.

[![Donate BTC](https://img.shields.io/badge/Donate-BTC-yellow.svg)](https://blockchain.info/address/3MTVHcDrbiwrp5N6rT2DwrMCXMBP3rT7ty) [![Latest GitHub release](https://img.shields.io/github/release/openvcash/vcash.svg)](https://github.com/openvcash/vcash/releases/latest) [![Build status](https://travis-ci.org/openvcash/vcash.svg?branch=master)](https://travis-ci.org/openvcash/vcash)  

https://vcash.info/  

What is Vcash?
---
Vcash is a decentralized internet currency that enables you to send money to anyone in the world, instantly, and at almost no cost.

Vcash features include [Peercoin](https://github.com/ppcoin/ppcoin) PoS, [Bitcoin](https://github.com/bitcoin/bitcoin) PoW consensus, a UDP layer, an off-chain transaction lock voting system called ZeroTime, an Incentive Reward voting system, and a client-side blending system called ChainBlender.

Docs and whitepapers
---
[The docs](https://docs.vcash.info/), their [source on github,](https://github.com/openvcash/docs.vcash.info) and [the whitepapers.](https://github.com/openvcash/papers)  

Read [common issues](docs/COMMON_ISSUES.md) if you're having problems related to the coin other than when trying to build from source.

Building from source
---
[Dependencies can be found here.](docs/DEPENDENCIES.md)  
Read [BUILDING](docs/BUILDING.md) before attempting to build from source.  

There are currently two ways to build the source code: [CMake](https://cmake.org/) and [Boost.](http://www.boost.org/build/)

CMake relies on the dependencies to be installed normally, while Boost-build requires you to build and compile dependencies into the [vcash/deps](deps) folder.  
The following instructions are only for CMake.

#### Windows
1. Install [the dependencies](docs/DEPENDENCIES.md) to their default locations.
2. Download and extract the [Source code (zip).](https://github.com/openvcash/vcash/releases/latest)
3. Run `cmake-gui`, select the source code and target build folders, any needed flags, then click configure/generate to start the build process.
4. Open `Vcash.sln` with Visual Studio, select `Release` as build type, and then press the build button to start building Vcash.

#### Linux & Mac
1. Install [the dependencies](docs/DEPENDENCIES.md) with your package manager.
2. Download the [Source code (tar.gz)](https://github.com/openvcash/vcash/releases/latest) to your `~/Downloads` folder.
3. Run the following commands from your terminal...
```
tar -xzf ~/Downloads/vcash-*.tar.gz
cd ~/Downloads/vcash-*/
cmake CMakeLists.txt
make
make install
```

When finished, you should be able to run `vcashd` from your terminal.  

**Arch Linux**  
[![The AUR PKGBUILD](https://img.shields.io/aur/version/vcash.svg)](https://aur.archlinux.org/packages/vcash/) is available, which builds and installs the source code from the latest release.

If you don't know how to install something from the Arch User Repository, [read this Arch wiki post](https://wiki.archlinux.org/index.php/AUR_helpers) or [this post on the forums.](https://forum.vcash.info/d/56-arch-linux-aur-pkgbuild-s)

License
---
Vcash is released under the terms of the AGPL-3.0 license. See [LICENSE](LICENSE) for more information.
