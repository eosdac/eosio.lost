#include "whitelist.hpp"

void whitelist::add(name account, vector<char> eth_address) {
    require_auth(_self);

    whitelist_table whitelist(_self, _self.value);

    eosio_assert(is_account(account), "Account does not exist");

    auto existing = whitelist.find(account.value);
    eosio_assert(existing == whitelist.end(), "Account is already on the whitelist");

    whitelist.emplace(_self, [&](whitelist_info &w) {
        w.account = account;
        w.eth_address = eth_address;
    });
}

void whitelist::remove(name account) {
    assert_minor_bp_auth();

    whitelist_table whitelist(_self, _self.value);

    eosio_assert(is_account(account), "Account does not exist");

    auto existing = whitelist.find(account.value);
    eosio_assert(existing != whitelist.end(), "Account is not on the whitelist");

    whitelist.erase(existing);
}

void whitelist::clear(uint64_t count){
    require_auth(_self);

    whitelist_table whitelist(_self, _self.value);

    uint16_t i = 0;
    auto itr = whitelist.begin();
    eosio_assert(itr != whitelist.end(), "Table is empty");

    while (itr != whitelist.end() && i <= count){
        itr = whitelist.erase(itr);
        i++;
    }
}

void whitelist::assert_minor_bp_auth(){


    producers_table producers("eosio"_n, "eosio"_n.value);

    auto idx = producers.get_index<"prototalvote"_n>();

    uint8_t bp_auths = 0;
    uint8_t required_auths = 8;
    uint8_t bp_check = 0;

    for ( auto it = idx.cbegin(); it != idx.cend() && 0 < it->total_votes && it->active() && bp_auths < required_auths && bp_check < 21; ++it ) {
        if (has_auth(it->owner)){
            bp_auths++;
        }

        bp_check++;
    }

    eosio_assert(bp_auths >= required_auths, "This action requires minor BP authentication");
}


EOSIO_DISPATCH( whitelist,
(add)(remove)(clear)
)
