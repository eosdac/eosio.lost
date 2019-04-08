#include <eosiolib/eosio.hpp>
#include <eosiolib/crypto.hpp>
#include <eosiolib/multi_index.hpp>
#include <eosiolib/transaction.hpp>
#include <eosiolib/asset.hpp>
#include <eosiolib/permission.h>

#define USE_KECCAK
#include "sha3/sha3.c"
#include "ecc/uECC.c"

using namespace eosio;
using namespace std;

typedef std::string ethereum_address;

#ifndef WAITING_PERIOD
#define WAITING_PERIOD 60 * 60 * 24 * 30
#endif

#define _STRINGIZE(x) #x
#define STRINGIZE(x) _STRINGIZE(x)

#ifdef WHITELISTCONTRACT
#define WHITELIST_CONTRACT STRINGIZE(WHITELISTCONTRACT)
#endif

#ifndef WHITELIST_CONTRACT
#define WHITELIST_CONTRACT "unusedaccnts"
#endif


class [[eosio::contract("eosio.lost")]] lostcontract : public contract {

private:

    TABLE verify_info{
            name              claimer;
            time_point_sec    added;
            public_key        new_key;
            uint8_t           updated;

            uint64_t primary_key() const { return claimer.value; }

            EOSLIB_SERIALIZE(verify_info,
                            (claimer)
                            (added)
                            (new_key)
                            (updated))
    };
    typedef multi_index<"verified"_n, verify_info> verifications_table;



#include "whitelist/defs.hpp"


    void assert_unused(name account);
    void assert_whitelisted(name account);
    void assert_active();
    std::string bytetohex(unsigned char *data, int len);

public:

    using contract::contract;

    ACTION updateauth(name claimer);

    ACTION verify(std::vector<char> sig, name account, public_key newpubkey, name rampayer);

    ACTION reset(name claimer);

    ACTION useaccount(name claimer);

    ACTION notify(name claimer, string msg);

    ACTION clear(uint64_t count);

};


//Authority Structs
namespace eosiosystem {

    struct key_weight {
        eosio::public_key key;
        uint16_t weight;

        // explicit serialization macro is not necessary, used here only to improve compilation time
        EOSLIB_SERIALIZE(key_weight, (key)(weight))
    };

    struct permission_level_weight {
        permission_level permission;
        uint16_t weight;

        // explicit serialization macro is not necessary, used here only to improve compilation time
        EOSLIB_SERIALIZE(permission_level_weight, (permission)(weight))
    };

    struct wait_weight {
        uint32_t wait_sec;
        uint16_t weight;

        // explicit serialization macro is not necessary, used here only to improve compilation time
        EOSLIB_SERIALIZE(wait_weight, (wait_sec)(weight))
    };

    struct authority {

        uint32_t threshold;
        vector <key_weight> keys;
        vector <permission_level_weight> accounts;
        vector <wait_weight> waits;

        EOSLIB_SERIALIZE(authority, (threshold)(keys)(accounts)(waits))
    };
}

