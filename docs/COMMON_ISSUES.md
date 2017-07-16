Common Issues
=====
**This is not for problems with the build process.**

Wallet Problems -- RENAME THIS
---
If you get errors when trying to run a fresh install, and you are running an older wallet (created before version `0.5.0.0`), then it is most likely not a deterministic wallet. To fix this, first close your wallet GUI/daemon, open your config.dat, and change the line that says `"deterministic": "1"` to `"deterministic": "0"`

**Paths to your Vcash data files**  
Linux or Mac: `~/.Vcash/data/`  
Windows: `%appdata%\Roaming\Vcash\`
