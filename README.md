Vcash
======
> A decentralized currency for the internet.

# What is Vcash?
Vcash is a decentralized currency for the internet. It enables you to send money to anywhere in the world instantly for almost no cost.

Vcash features include [Peercoin](https://github.com/ppcoin/ppcoin) PoS, [Bitcoin](https://github.com/bitcoin/bitcoin) PoW consensus, a UDP layer, an off-chain transaction lock voting system called ZeroTime, an Incentive Reward voting system, and a client-side blending system called ChainBlender.

|Important links|
|:---:|
|[Official website](https://vcash.info/)|
|[The newest downloads can be found here.](https://github.com/openvcash/vcash/releases)|
|[The docs can be found here.](https://github.com/openvcash/docs.vcash.info)|
|[The whitepapers can be found here.](https://github.com/openvcash/papers)|

## Building from source
If you have any questions or issues with the build process, read [BUILDING.md](docs/BUILDING.md)  
[The list of dependencies can be found here.](docs/DEPENDENCIES.md)

### Windows
1. Download and extract the newest [Source code zip](https://github.com/openvcash/vcash/releases)
2. Install the [listed version of the dependencies](docs/DEPENDENCIES.md) to their normal locations
3. Download and install the latest release of [Cmake](https://cmake.org/download/)
4. Run the Cmake GUI on the `CMakeLists.txt` file inside of the source code to start the build/installation.

**PLACEHOLDER, Windows section is unfinished**

### Linux
**Ubuntu** used as an example.

1. Download the newest [Source code tar.gz](https://github.com/openvcash/vcash/releases) to your `~/Downloads` folder.
2. Install [the correct dependencies](docs/DEPENDENCIES.md).
```shell
sudo apt-get update && sudo apt-get upgrade
sudo apt-get install build-essential cmake boost-defaults db-defaults openssl
```
3. Run the following commands from your terminal...
```shell
tar -xzf ~/Downloads/vcash-*.tar.gz
cd ~/Downloads/vcash-*/
cmake -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_INSTALL_BINDIR=bin -DCMAKE_INSTALL_LIBDIR=lib/vcash CMakeLists.txt
make
sudo make install
```

When finished, you should be able to run `vcashd` from your terminal.  

**Arch**  
[Install from the AUR](https://aur.archlinux.org/packages/vcash/), which builds the latest release from the source code automatically.

If you don't know how to install something from the Arch User Repository, [read this wiki post](https://wiki.archlinux.org/index.php/AUR_helpers) or [this post on the forums.](https://forum.vcash.info/d/56-arch-linux-aur-pkgbuild-s)

### Mac
**PLACEHOLDER, Mac section is unfinished**
