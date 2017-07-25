# Bash RPC script
The Bash RPC script is used to send commands, and read out information from the Vcash daemon.  
Please note that `.sh` files do not work natively on Windows.

**Dependency:** [jq](https://stedolan.github.io/jq/)

**Usage:** Run `./rpc.sh -m <method>` or `./rpc.sh -m <method> -p <params>` with Bash (your terminal).

## Examples
Desired output|Command in Bash
:---:|:---:
Return general information about the node|`./rpc.sh -m getinfo`
Return information about the current incentive state|`./rpc.sh -m getincentiveinfo`
Send an amount of coins to an address|`./rpc.sh -m sendtoaddress -p '["address",amount]'`

More commands can be found in [the docs](https://docs.vcash.info/), or at their [git source.](https://github.com/openvcash/docs.vcash.info)
