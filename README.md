# curvy_mining

This repository contains experimental mining and cryptographic utilities.

#Building

To build gHash run the following command:

```bash
./build.sh
```

#Environment

Set up the following environmental variables, or edit them in the python script:

```bash
export RPC_USER="rpcuser"
export RPC_PASS="verylongrpcpassword"
```

#Mining

You may run:

```bash
python python/mining.py   <Your_SCRIPTPUBKEY_goes_here>
```

This will attempt to mine one block. You may want to run it in a loop.


