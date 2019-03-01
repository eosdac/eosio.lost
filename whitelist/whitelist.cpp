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
    require_auth(_self);

    whitelist_table whitelist(_self, _self.value);

    eosio_assert(is_account(account), "Account does not exist");

    auto existing = whitelist.find(account.value);
    eosio_assert(existing != whitelist.end(), "Account is not on the whitelist");

    whitelist.erase(existing);
}

void whitelist::clear(){
    require_auth(_self);

    whitelist_table whitelist(_self, _self.value);

    auto itr = whitelist.begin();
    while (itr != whitelist.end()){
        itr = whitelist.erase(itr);
    }
}


EOSIO_DISPATCH( whitelist,
(add)(remove)(clear)
)
