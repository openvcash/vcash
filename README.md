Vcash
======
> A decentralized currency for the internet.

[![Donate](https://img.shields.io/badge/Donate-BTC-yellow.svg)](https://blockchain.info/address/3MTVHcDrbiwrp5N6rT2DwrMCXMBP3rT7ty) [![GitHub release](https://img.shields.io/github/release/openvcash/vcash.svg)](https://github.com/openvcash/vcash/releases/latest)  

https://vcash.info/  

What is Vcash?
---
Vcash is a decentralized currency for the internet that enables you to send money to anywhere in the world instantly, for almost no cost.

Vcash features include [Peercoin](https://github.com/ppcoin/ppcoin) PoS, [Bitcoin](https://github.com/bitcoin/bitcoin) PoW consensus, a UDP layer, an off-chain transaction lock voting system called ZeroTime, an Incentive Reward voting system, and a client-side blending system called ChainBlender.

[The docs](https://docs.vcash.info/) [(source)](https://github.com/openvcash/docs.vcash.info), and [the whitepapers.](https://github.com/openvcash/papers)  
Read [common issues](docs/COMMON_ISSUES.md) if you're having problems related to the features of the coin itself.

Building from source
---
**WARNING: read [BUILDING.md](docs/BUILDING.md) before attempting to build from source.**  
[The list of dependencies can be found here.](docs/DEPENDENCIES.md)

#### Windows
1. Install [the dependencies](docs/DEPENDENCIES.md) to their normal locations.
2. Download and extract the newest [Source code (zip).](https://github.com/openvcash/vcash/releases/latest)
3. Run the Cmake GUI on the `CMakeLists.txt` file inside of the source code to start the build/installation.

**PLACEHOLDER, Windows section is unfinished**

#### Linux
Example for the **Ubuntu** build process.

1. Install [the dependencies](docs/DEPENDENCIES.md).
2. Download the newest [Source code (tar.gz)](https://github.com/openvcash/vcash/releases/latest) to your `~/Downloads` folder.
```
sudo apt-get update && sudo apt-get upgrade
sudo apt-get install build-essential cmake boost-defaults db-defaults openssl
```
3. Run the following commands from your terminal...
```
tar -xzf ~/Downloads/vcash-*.tar.gz
cd ~/Downloads/vcash-*/
cmake -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_INSTALL_BINDIR=bin -DCMAKE_INSTALL_LIBDIR=lib/vcash CMakeLists.txt
make
sudo make install
```

When finished, you should be able to run `vcashd` from your terminal.  

**Arch-based**  
[![AUR](https://img.shields.io/aur/version/vcash.svg)](https://aur.archlinux.org/packages/vcash/) is available, which builds and installs the source code from the latest release.

If you don't know how to install something from the Arch User Repository, [read this Arch wiki post](https://wiki.archlinux.org/index.php/AUR_helpers) or [this post on the forums.](https://forum.vcash.info/d/56-arch-linux-aur-pkgbuild-s)

#### Mac
**PLACEHOLDER, Mac section is unfinished**
