#include "eosio.lost.hpp"
#include <eosiolib/print.hpp>
#include "trezor-crypto/base58.c"
#include "trezor-crypto/memzero.c"


void lostcontract::updateauth(name claimer) {
    verifications_table verifications(_self, _self.value);

    auto verification = verifications.find(claimer.value);

    eosio_assert(verification != verifications.end(), "Account not verified");

    time_point_sec deadline{now() - WAITING_PERIOD};

    eosio_assert(verification->added < deadline, "Thirty day waiting period has not passed");
    eosio_assert(verification->updated == 0, "Already updated this lost key");
    eosio_assert(is_account(claimer), "Account does not exist");

    assert_whitelisted(claimer);

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
    // Verify that the contract is still active
    assert_active();
    // copy public key
    public_key pkeycopy = newpubkey;
    unsigned char to_encode[37];
    memcpy(to_encode, pkeycopy.data.data(), 33);

    // Calculate and concatenate checksum
    checksum160 checksum = ripemd160((const char *)pkeycopy.data.begin(), 33);
    memcpy(to_encode + 33, checksum.extract_as_byte_array().data(), 4);

    // convert to base58
    char b58[51];
    size_t b58sz = 51;
    b58enc(b58, &b58sz, (const uint8_t *)to_encode, 37);

    require_auth(rampayer);
    require_recipient(account);

    verifications_table verifications(_self, _self.value);

    eosio_assert(is_account(account), "Account does not exist");


    auto verification = verifications.find(account.value);
    eosio_assert(verification == verifications.end(), "Account already verified");

    assert_whitelisted(account);

    // Make sure the account hasn't been used
    assert_unused(account);

    /////////////////////////
    // Verify signature

    // ETH signatures sign the keccak256 hash of a message so we have to do the same
    sha3_ctx shactx;
    capi_checksum256 msghash;
    char tmpmsg[128];
    sprintf(tmpmsg, "%u,%u,I lost my EOS genesis key and I request a key reset to EOS%s", tapos_block_num(), tapos_block_prefix(), b58);
//    sprintf(tmpmsg, "I lost my EOS genesis key and I request a key reset to EOS%s", b58);

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
    std::string calculated_eth_address = bytetohex(eth_address, 20);

    // verify ETH key matches account
    whitelist_table whitelist(name(WHITELIST_CONTRACT), name(WHITELIST_CONTRACT).value);
    auto white_it = whitelist.find( account.value );
    eosio_assert( white_it != whitelist.end(), "Account is not in the whitelist");

    // verify calculated address matches whitelist
    std::string lowercase_whitelist = bytetohex((unsigned char *)white_it->eth_address.data(), white_it->eth_address.size());
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


    string msg_en = "EOS lost key recovery: This account has been scheduled for a key swap by the holder of \
 the Ethereum private key associated with it. To cancel the swap, authorize any transaction \
 within 30 days (eg: vote, transfer, stake, etc).";
    string msg_cn = "恢复EOS丢失密钥：此帐户已安排由与其关联的以太坊私钥的持有者进行密钥交换。 要取消交换，请在30天内授权交易（例如：通过投票，转让，投注等）。";
    string msg_kr = "이오스 분실키 복구: 이 계정은 여결된 이더리움 프라이빗 키 홀더의 결정에 따라 키 교환을 예정 중 입니다. 교환을 취소하기 위해선, 30일내에 거래를 재가하세요. (예: 투표, 코인 전송, 스테이킹 등등)";

    action(permission_level{_self, "active"_n},
           _self, "notify"_n,
           std::make_tuple(
                   account,
                   msg_en
           )).send();

    action(permission_level{_self, "active"_n},
           _self, "notify"_n,
           std::make_tuple(
                   account,
                   msg_kr
           )).send();

    action(permission_level{_self, "active"_n},
           _self, "notify"_n,
           std::make_tuple(
                   account,
                   msg_cn
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

    verifications.get(claimer.value, "Account is not verified, will not notify");
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

void lostcontract::clear(uint64_t count){
    require_auth(_self);

    verifications_table verifications(_self, _self.value);

    uint16_t i = 0;
    auto itr = verifications.begin();
    eosio_assert(itr != verifications.end(), "Table is empty");

    while (itr != verifications.end() && i <= count){
        itr = verifications.erase(itr);
        i++;
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

void lostcontract::assert_whitelisted(name account) {
    whitelist_table whitelist(name(WHITELIST_CONTRACT), name(WHITELIST_CONTRACT).value);
    whitelist.get(account.value, "Account is not whitelisted (assert_whitelisted failed)");
}

void lostcontract::assert_active() {
    eosio_assert(now() < 1587340800, "Key recovery is no longer available");
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
(updateauth)(verify)(reset)(clear)(useaccount)(notify)
)
