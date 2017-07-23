# Vcash bash RPC script

Dependencies
```
jq
```

Make it executable
```
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
