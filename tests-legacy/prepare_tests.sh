#!/bin/bash
cd ..
make clean
make -j DEBUG=1  # compile optionally with PRINTF
mv bin/ tests-legacy/bitcoin-bin
make clean
make -j DEBUG=1 COIN=bitcoin_testnet_lib
mv bin/ tests-legacy/bitcoin-testnet-bin
