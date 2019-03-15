var request = require('request');
var csv = require("csvtojson");



var config = {
    endpoint: 'https://jungle2.cryptolions.io',
    contract: 'keyrecovery1'
};



(async function(){
    var snapshotRecords = {};
    try{
        //EOS Authority Snapshot generated for launch
        //https://github.com/eosauthority/genesis/blob/master/snapshot-files/final/2/snapshot.csv
        var snapshots = await csv({noheader:true}).fromFile('snapshot.csv');
        
        snapshots.forEach(function(snapshot) 
        { 
            snapshotRecords[snapshot.field2] = snapshot;
        });
    }catch(error){
        console.log('Error reading snapshot.csv file');
        return;
    }
    
    try{
        var params = {
            code: config.contract,
            scope: config.contract,
            table:'whitelist',
            table_key: '',
            lower_bound: '',
            upper_bound: '',
            limit: 1000,
            json: true
        };
        
        do {
            var tableRows = await getTableRows(params);            
            
            if(!tableRows || !tableRows.rows){
                throw "Error fetching table rows";
            }
            
            tableRows.rows.forEach(function(row) 
            { 
                snapshotRecord = snapshotRecords[row.account];
                if(!snapshotRecord){
                    throw "Record not found on snapshot.csv: " + row.account;
                }else if(snapshotRecord.field1 != row.eth_address){
                     throw "Ethereum address mismatch: " + row.account;
                }
            });  

            if(tableRows.more){
                more = 1;
                params.lower_bound = row.account;
            }else{
                more = 0;
            }
            

        }while (more ==1)
            
            
        console.log('snapshot.csv matched with whitelist table rows');    
    }catch(error){
        console.log(error);
        return;
    }
    
    
    
    
    console.log(tableRows)
    
})();

function getTableRows(params) {
    return new Promise(function(resolve, reject) { 
        request({
        url: config.endpoint + '/v1/chain/get_table_rows', 
        method: "POST", 
        json: true, 
        timeout: 5000,
        body: params
    }, function(error, response, body) {
            resolve(body);
        });
    });
}