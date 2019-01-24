if (process.argv.length < 3) {
    console.log(`
        Usage: node flag-hacked-eth.js [ETH_ADDRESS]
        Example: node flag-hacked-eth.js 0x751DFa7A1BE617Df0520adE8f68bbd007C6b6556
    `);
    process.exit(1);
}
const fs = require('fs');
const fetch = require('node-fetch');
const cheerio = require('cheerio');

const Web3 = require('web3');
const web3 = new Web3("https://mainnet.infura.io/v3/a8c1c0a943274566bb4c530477ff225c");

const EOS_CONTRACT = "0x86fa049857e0209aa7d9e616f7eb3b3b78ecfdb0";

main();

async function main () {
    const abi = JSON.parse(fs.readFileSync("eos-token-abi.json", "utf-8"));
    const contract = new web3.eth.Contract(abi, "0x86Fa049857E0209aa7D9e616F7eb3b3B78ECfdb0");
    const address = process.argv[2];

    const wei = await web3.eth.getBalance(address);
    if (wei < 1e17)
        console.log("Balance less than 0.1 ether");
    else 
        console.log("Balance greater than 0.1 ether");

    const scrape = await fetch(`https://etherscan.io/address/${address}`)
        .then(r => r.text());
    
    const $ = cheerio.load(scrape);

    const addresses = []; 
    $(".address-tag").each(function () { 
        addresses.push($(this).text());
    });
    const transactions = addresses.filter(a => a.length == 66);

    const promises = []
    for (const i in transactions) {
        const prom = web3.eth.getTransactionReceipt(transactions[i]);
        promises.push(prom);
    }
    const receipts = await Promise.all(promises);

    let failed_eos_transfers = 0;
    receipts.forEach(function (receipt) {
        if (receipt.to == EOS_CONTRACT && receipt.status === false)
            failed_eos_transfers += 1;
    });
    console.log(`There were ${failed_eos_transfers} failed EOS transfers`);

    if (wei < 1e17 && failed_eos_transfers > 5)
        console.log("This account was likely hacked");
    else if (wei < 1e17 && failed_eos_transfers > 0)
        console.log("This account may have been hacked");
    else
        console.log("This account was not hacked");

}
