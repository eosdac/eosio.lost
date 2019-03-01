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

    void assert_minor_bp_auth();

public:

    using contract::contract;

    ACTION add(name address, vector<char> eth_address);

    ACTION remove(name account);

    ACTION clear();


};


struct producer_info {
    name owner;
    double total_votes = 0;
    eosio::public_key producer_key; /// a packed public key object
    bool is_active = true;
    std::string url;
    uint32_t unpaid_blocks = 0;
    time_point last_claim_time;
    uint16_t location = 0;

    uint64_t primary_key() const { return owner.value; }

    double by_votes() const { return is_active ? -total_votes : total_votes; }

    bool active() const { return is_active; }

    void deactivate() {
        producer_key = public_key();
        is_active = false;
    }

    // explicit serialization macro is not necessary, used here only to improve compilation time
    EOSLIB_SERIALIZE( producer_info, (owner)(total_votes)(producer_key)(is_active)(url)
            (unpaid_blocks)(last_claim_time)(location)
    )
};

typedef eosio::multi_index<"producers"_n, producer_info,
        indexed_by<"prototalvote"_n, const_mem_fun < producer_info, double, &producer_info::by_votes> >
>
producers_table;