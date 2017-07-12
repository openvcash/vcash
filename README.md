# Vcash

> A decentralized currency for the internet.

This project is a codebase rewrite/enhancment using:
* [Peercoin](https://github.com/ppcoin/ppcoin) PoS & [Bitcoin](https://github.com/bitcoin/bitcoin) PoW consensus
* an UDP layer
* an off-chain transaction lock voting system called ZeroTime
* an Incentive Reward voting system
* a client-side blending system called ChainBlender

[The newest downloads can be found here.](https://github.com/openvcash/vcash/releases)

---
## Building from source
If you have any issues with the build process, [read the docs.](docs/build-problems.md)

**The list of dependencies** [can be found here.](docs/dependencies.md)

### Windows
1. Download and extract the newest [Source code zip](https://github.com/openvcash/vcash/releases)
2. Install the [listed version of the dependencies](docs/dependencies.md) to their normal locations
3. Download and install the latest release of [Cmake](https://cmake.org/download/)
4. Run the Cmake GUI on the `CMakeLists.txt` file inside of the source code to start the build/installation.

**PLACEHOLDER, Windows section is unfinished**

### Linux
**Ubuntu** used as an example.

1. Download the newest [Source code tar.gz](https://github.com/openvcash/vcash/releases) to your `~/Downloads` folder.
2. Install [the correct dependencies](docs/dependencies.md).
```
sudo apt-get update && sudo apt-get upgrade
sudo apt-get install cmake make libboost-all-dev libdb-dev libdb++-dev openssl leveldb
```
3. Run the following commands from your terminal...
```
tar -xzf ~/Downloads/vcash-*.tar.gz
cd ~/Downloads/vcash-*/
cmake -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_INSTALL_BINDIR=bin -DCMAKE_INSTALL_LIBDIR=lib/vcash CMakeLists.txt
make
make install
```

When finished, you should be able to run `vcashd` from your terminal.  

**Arch**  
[Install from the AUR](https://aur.archlinux.org/packages/vcash/), which builds the latest release from the source code automatically.

If you don't know how to install something from the Arch User Repository, [read this wiki post](https://wiki.archlinux.org/index.php/AUR_helpers) or [this post on the forums.](https://forum.vcash.info/d/56-arch-linux-aur-pkgbuild-s)

### Mac
**PLACEHOLDER, Mac section is unfinished**
