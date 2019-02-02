#include "whitelist.hpp"

void whitelist::add(name account, vector<char> eth_address, asset value) {
    require_auth(_self);

    whitelist_table whitelist(_self, _self.value);

    eosio_assert(is_account(account), "Account does not exist");

    auto existing = whitelist.find(account.value);
    eosio_assert(existing == whitelist.end(), "Account is already on the whitelist");

    whitelist.emplace(_self, [&](whitelist_info &w) {
        w.account = account;
        w.eth_address = eth_address;
        w.value = value;
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



EOSIO_DISPATCH( whitelist,
(add)(remove)
)
