# Vcash bash RPC script

Dependencies
```
jq
```

Get the script and make it executable
```
wget https://raw.githubusercontent.com/whphhg/vcash-bash-rpc/master/rpc.sh
chmod +x rpc.sh
```

Usage
```
./rpc.sh -m <method> -p <params>
./rpc.sh -m getincentiveinfo
./rpc.sh -m getblockhash -p 220200
./rpc.sh -m sendtoaddress -p '["address",amount]'
./rpc.sh -m listreceivedbyaccount -p '{"minconf":1,"includeempty":true}'
```
