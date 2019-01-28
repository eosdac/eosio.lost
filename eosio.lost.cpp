#include "eosio.lost.hpp"
#include <eosiolib/print.hpp>
#include "trezor-crypto/base58.c"
#include "trezor-crypto/memzero.c"
#include "trezor-crypto/ripemd160.c"

void lostcontract::add(name account, string eth_address, asset value) {
    require_auth(_self);

    whitelist_table whitelist(_self, _self.value);

    eosio_assert(is_account(account), "Account does not exist");

    auto existing = whitelist.find(account.value);
    eosio_assert(existing == whitelist.end(), "Address is already on the whitelist");

    whitelist.emplace(_self, [&](whitelist_info &w) {
        w.account = account;
        w.eth_address = eth_address;
        w.value = value;
    });
}

void lostcontract::remove(name account) {
    require_auth(_self);

    whitelist_table whitelist(_self, _self.value);

    eosio_assert(is_account(account), "Account does not exist");

    auto existing = whitelist.find(account.value);
    eosio_assert(existing != whitelist.end(), "Address is not on the whitelist");

    whitelist.erase(existing);
}


void lostcontract::updateauth(name claimer) {
    verifications_table verifications(_self, _self.value);
    whitelist_table whitelist(_self, _self.value);

    auto verification = verifications.find(claimer.value);

    eosio_assert(verification != verifications.end(), "Account not verified");

    time_point_sec deadline{now() - WAITING_PERIOD};

    eosio_assert(verification->added < deadline, "Thirty day waiting period has not passed");
    eosio_assert(verification->updated == 0, "Already updated this lost key");
    eosio_assert(is_account(claimer), "Account does not exist");

    auto whitelisted = whitelist.get(claimer.value, "Account is not whitelisted");

    // Make sure the account hasn't been used
    assert_unused(claimer);


    vector <eosiosystem::key_weight> keys;
    eosiosystem::key_weight kw{
            .key = verification->new_key,
            .weight = (uint16_t) 1,
    };
    keys.push_back(kw);

    eosiosystem::authority new_authority{
            .threshold = (uint32_t) 1,
            .keys = keys,
            .accounts = {},
            .waits = {}
    };

    action(permission_level{verification->claimer, "owner"_n},
           "eosio"_n, "updateauth"_n,
           std::make_tuple(
                   verification->claimer,
                   "active"_n,
                   "owner"_n,
                   new_authority
           )).send();

    action(permission_level{verification->claimer, "owner"_n},
           "eosio"_n, "updateauth"_n,
           std::make_tuple(
                   verification->claimer,
                   "owner"_n,
                   name{0},
                   new_authority
           )).send();


    // Mark this verification as proposed
    verifications.modify(verification, same_payer, [&](verify_info &v){
        v.updated = 1;
    });
}


void lostcontract::verify(std::vector<char> sig, name account, public_key newpubkey, name rampayer) {
    // copy public key
    public_key pkeycopy = newpubkey;
    unsigned char to_encode[37];
    memcpy(to_encode, pkeycopy.data.data(), 33);

    // add ripemd160 checksum to end of key
    uint8_t hash_output[20];
    ripemd160((uint8_t *)pkeycopy.data.begin(), 33, hash_output);
    memcpy(to_encode + 33, hash_output, 4);

    // convert to base58
    char b58[51];
    size_t b58sz = 51;
    b58enc(b58, &b58sz, (const uint8_t *)to_encode, 37);

    require_auth(rampayer);
    require_recipient(account);

    verifications_table verifications(_self, _self.value);
    whitelist_table whitelist(_self, _self.value);

    eosio_assert(is_account(account), "Account does not exist");

    auto whitelisted = whitelist.get(account.value, "Account is not whitelisted");

    auto verification = verifications.find(account.value);
    eosio_assert(verification == verifications.end(), "Account already verified");

    // Make sure the account hasn't been used
    assert_unused(account);

    /////////////////////////
    // Verify signature

    // ETH signatures sign the keccak256 hash of a message so we have to do the same
    sha3_ctx shactx;
    capi_checksum256 msghash;
    char tmpmsg[128];
    sprintf(tmpmsg, "%u,%u,I lost my EOS genesis key and I request a key reset to EOS%s", tapos_block_num(), tapos_block_prefix(), b58);

    //Add prefix and length of signed message
    char message[128];
    sprintf(message, "%s%s%d%s", "\x19", "Ethereum Signed Message:\n", strlen(tmpmsg), tmpmsg);

    rhash_keccak_256_init(&shactx);
    rhash_keccak_update(&shactx, (const unsigned char*)message, strlen(message)); // ignore the null terminator at the end of the string
    rhash_keccak_final(&shactx, msghash.hash);

    // Recover the compressed ETH public key from the message and signature
    uint8_t compressed_pubkey[34];
    uint8_t pubkey[64];
    auto res = recover_key(
        &msghash,
        sig.data(),
        sig.size(),
        (char*)compressed_pubkey,
        34
    );
    eosio_assert(res == 34, "Recover key failed");

    // Decompress the ETH pubkey
    uECC_decompress(compressed_pubkey+1, pubkey, uECC_secp256k1());

    // Calculate the hash of the pubkey
    capi_checksum256 pubkeyhash;
    rhash_keccak_256_init(&shactx);
    rhash_keccak_update(&shactx, pubkey, 64);
    rhash_keccak_final(&shactx, pubkeyhash.hash);

    // last 20 bytes of the hashed pubkey = ETH address
    uint8_t eth_address[20];
    memcpy(eth_address, pubkeyhash.hash + 12, 20);

    // convert to human readable form
    std::string calculated_eth_address = "0x" + bytetohex(eth_address, 20);

    // verify ETH key matches account
    auto white_it = whitelist.find( account.value );
    eosio_assert( white_it != whitelist.end(), "Account is not in the whitelist");

    // verify calculated address matches whitelist
    std::string lowercase_whitelist = white_it->eth_address;
    std::for_each(lowercase_whitelist.begin(), lowercase_whitelist.end(), [](char & c){
        c = tolower(c);
    });

    print(calculated_eth_address.c_str(), ":", lowercase_whitelist.c_str());
    eosio_assert( calculated_eth_address == lowercase_whitelist, "Message was not properly signed by the ETH key for the account" );

    // Once all checks have passed, store the key change information
    verifications.emplace(rampayer, [&](verify_info &v){
        v.claimer  = account;
        v.added    = time_point_sec(now());
        v.new_key  = newpubkey;
        v.updated  = 0;
    });


    string msg = "This account has been scheduled for a key swap in 30 days by the holder of the Ethereum private key\
 associated with it. To cancel the swap, prove your ownership of this account by authorizing any transaction within\
 30 days.";
    action(permission_level{_self, "active"_n},
           _self, "notify"_n,
           std::make_tuple(
                   account,
                   msg
           )).send();

}

void lostcontract::useaccount(name claimer){
    require_auth(claimer);
}

void lostcontract::notify(name claimer, string msg){
    require_auth(_self);
    require_recipient(claimer);

    verifications_table verifications(_self, _self.value);

    eosio_assert(is_account(claimer), "Account does not exist");

    auto verification = verifications.get(claimer.value, "Account is not verified, will not notify");
}

void lostcontract::reset(name claimer){
    require_auth(_self);

    verifications_table verifications(_self, _self.value);
    auto verification = verifications.find(claimer.value);

    eosio_assert(verification != verifications.end(), "Account not verified");

    verifications.modify(verification, same_payer, [&](verify_info &v){
        v.updated = 0;
    });
}

void lostcontract::clear(){
    require_auth(_self);

    verifications_table verifications(_self, _self.value);

    auto itr = verifications.begin();
    while (itr != verifications.end()){
        itr = verifications.erase(itr);
    }
}

void lostcontract::assert_unused(name account) {
    int64_t last_used_a = get_permission_last_used(account.value, "active"_n.value);
//    print(" last_used_a ");
//    print(last_used_a);
    int64_t last_used_o = get_permission_last_used(account.value, "owner"_n.value);
//    print(" last_used_o ");
//    print(last_used_o);
    int64_t c_time = get_account_creation_time(account.value);
//    print(" c_time ");
//    print(c_time);

    eosio_assert(last_used_a == c_time && last_used_o == c_time, "EOS account has been used to authorise transactions");
}

std::string lostcontract::bytetohex(unsigned char *data, int len) {
    constexpr char hexmap[] = {'0', '1', '2', '3', '4', '5', '6', '7',
                               '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    std::string s(len * 2, ' ');
    for (int i = 0; i < len; ++i) {
        s[2 * i]     = hexmap[(data[i] & 0xF0) >> 4];
        s[2 * i + 1] = hexmap[data[i] & 0x0F];
    }
    return s;
}


EOSIO_DISPATCH( lostcontract,
(add)(updateauth)(verify)(reset)(clear)(useaccount)(notify)
)
