#ifdef NOWHITELISTTABLE
#define CTABLE struct
#else
#define CTABLE TABLE
#endif

CTABLE whitelist_info{
        name              account;
        vector<char>      eth_address;

        uint64_t primary_key() const { return account.value; }

        EOSLIB_SERIALIZE(whitelist_info,
                        (account)
                        (eth_address))
};
typedef multi_index<"whitelist"_n, whitelist_info> whitelist_table;
