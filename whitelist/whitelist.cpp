#include "whitelist.hpp"

void whitelist::add(name account, vector<char> eth_address) {
    require_auth(get_self());

    whitelist_table whitelist(get_self(), get_self().value);

    eosio_assert(is_account(account), "Account does not exist");

    auto existing = whitelist.find(account.value);
    eosio_assert(existing == whitelist.end(), "Account is already on the whitelist");

    whitelist.emplace(_self, [&](whitelist_info &w) {
        w.account = account;
        w.eth_address = eth_address;
    });
}

void whitelist::remove(name account) {
    require_auth(get_self());

    whitelist_table whitelist(get_self(), get_self().value);

    auto existing = whitelist.find(account.value);
    eosio_assert(existing != whitelist.end(), "Account is not on the whitelist");

    whitelist.erase(existing);
}

void whitelist::clear(uint64_t count){
    require_auth(get_self());

    whitelist_table whitelist(get_self(), get_self().value);

    uint16_t i = 0;
    auto itr = whitelist.begin();
    eosio_assert(itr != whitelist.end(), "Table is empty");

    while (itr != whitelist.end() && i <= count){
        itr = whitelist.erase(itr);
        i++;
    }
}


EOSIO_DISPATCH( whitelist,
(add)(remove)(clear)
)
