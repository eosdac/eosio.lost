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
#include "defs.hpp"

public:
    using contract::contract;

    ACTION add(name address, vector<char> eth_address);

    ACTION remove(name account);

    ACTION clear(uint64_t count);
};
