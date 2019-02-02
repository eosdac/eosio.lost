#include <eosiolib/eosio.hpp>
#include <eosiolib/crypto.hpp>
#include <eosiolib/multi_index.hpp>
#include <eosiolib/transaction.hpp>
#include <eosiolib/asset.hpp>
#include <eosiolib/permission.h>


using namespace eosio;
using namespace std;

class [[eosio::contract("whitelist")]] whitelist : public contract {

private:

    TABLE whitelist_info{
            name              account;
            vector<char>      eth_address;
            asset             value;

            uint64_t primary_key() const { return account.value; }

            EOSLIB_SERIALIZE(whitelist_info,
                            (account)
                            (eth_address)
                            (value))
    };
    typedef multi_index<"whitelist"_n, whitelist_info> whitelist_table;

public:

    using contract::contract;

    ACTION add(name address, vector<char> eth_address, asset value);

    ACTION remove(name account);

    ACTION clear();


};

