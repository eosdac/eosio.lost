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
