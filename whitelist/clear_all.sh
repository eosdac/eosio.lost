#!/usr/bin/env bash

CLEOS="cleos -u http://jungle.eosdac.io:8882"
PROPOSER="evilmikehere"
WHITELIST_CONTRACT="whitelist111"
WALLET_NAME="jungle"


while [ 1 ]
do
$CLEOS push action -f $WHITELIST_CONTRACT clear '[150]' -p $WHITELIST_CONTRACT
done