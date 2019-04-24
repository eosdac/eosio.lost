const config = require('./config');

const csv = require('csv-parser');
const fs = require('fs');
const {Api, JsonRpc} = require('eosjs');
const JsSignatureProvider = require('eosjs/dist/eosjs-jssig');
const fetch = require('node-fetch');
const {TextEncoder, TextDecoder} = require('util');

const entries = [], tx_actions = [], failed_batches = [];

const signatureProvider = new JsSignatureProvider.default([config.private_key]);
const rpc = new JsonRpc(config.endpoint, {fetch});
const api = new Api({rpc, signatureProvider, textDecoder: new TextDecoder(), textEncoder: new TextEncoder()});

const whitelist_contract = config.contract;

const process_batches = (async (tx_actions) => {
    console.log(`Processing ${tx_actions.length} batches`)

    while (tx_actions.length){
        const actions =  tx_actions.pop();
        try {
            const res = await api.transact({
                actions
            }, {blocksBehind: 3, expireSeconds: 180});

            console.log(res);
        }
        catch (e){
            failed_batches.push(actions);
            console.log(`ERROR: ${e.message}`)
        }

    }
})

const parser = csv({
    mapHeaders: ({header, index}) => {
        return header.toLowerCase().replace(' ', '_')
    }
})
    .on('data', (row) => {
        // console.log(row)
        entries.push({'address': row.account, 'eth_address': row.ethereum_address.substr(2)})
    })
    .on('end', () => {

        while (entries.length > 0) {
            const batch = entries.splice(0, 250);
            // console.log(batch)

            const actions = batch.map((a) => {
                return {
                    account: whitelist_contract,
                    name: 'add',
                    authorization: [{actor: whitelist_contract, permission: 'active'}],
                    data: a
                }
            });

            tx_actions.push(actions)
        }

        console.log('done');


        process_batches(tx_actions);

    });


fs.createReadStream('./snapshot.csv')
    .pipe(parser);