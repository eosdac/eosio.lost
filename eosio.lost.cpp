

#include "eosio.lost.hpp"

void lostcontract::add(name account, string eth_address, asset value) {
    require_auth(_self);

    whitelist_table whitelist(_self, _self.value);

	eosio_assert(is_account(account), "Account does not exist");

    auto existing = whitelist.find(account.value);
    eosio_assert(existing == whitelist.end(), "Address is already on the whitelist");

        whitelist.emplace(_self, [&](whitelist_info &w){
            w.account  = account;
            w.eth_address = eth_address;
            w.value = value;
    });
}


void lostcontract::propose(name claimer) {
        verifications_table verifications(_self, _self.value);
        producers_table producers("eosio"_n, "eosio"_n.value);

        auto verification = verifications.find(claimer.value);

        eosio_assert(verification != verifications.end(), "Account not verified");

        time_point_sec deadline{now() - WAITING_PERIOD};

        eosio_assert(verification->added < deadline, "Thirty day waiting period has not passed");
        eosio_assert(verification->proposed == 0, "Already proposed this lost key");


        // Create transaction to be proposed

        time_point_sec expire{now() + PROPOSAL_EXPIRY};

        transaction trx;
        trx.expiration = expire;
        trx.ref_block_num = 0;
        trx.ref_block_prefix = 0;

        vector<eosiosystem::key_weight> keys;
        eosiosystem::key_weight kw {
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

        action act_active = action(permission_level{verification->claimer, "owner"_n},
                                   "eosio"_n, "updateauth"_n,
                                   std::make_tuple(
                                           verification->claimer,
                                           "active"_n,
                                           "owner"_n,
                                           new_authority
                                   ));

        action act_owner = action(permission_level{verification->claimer, "owner"_n},
                                   "eosio"_n, "updateauth"_n,
                                   std::make_tuple(
                                           verification->claimer,
                                           "owner"_n,
                                           name{0},
                                           new_authority
                                   ));

        trx.actions.push_back(act_active);
        trx.actions.push_back(act_owner);




        // create a wrap transaction

        transaction wrap;
        wrap.expiration = expire;
        wrap.ref_block_num = 0;
        wrap.ref_block_prefix = 0;
        vector<permission_level> perms;
        perms.push_back(permission_level{"eosio"_n, "active"_n});
        perms.push_back(permission_level{"eosio.wrap"_n, "active"_n});
        wrap.actions.push_back(action(perms,
                                          "eosio.wrap"_n, "exec"_n,
                                          std::make_tuple(
                                                  "eosio"_n,
                                                  trx
                                          )));




        // Create the msig inline from here
        // Get the top 30 bps for the requested list

        vector<permission_level> requested;
        auto by_votes = producers.get_index<"prototalvote"_n>();
        auto prod_itr = by_votes.begin();

//        requested.push_back(permission_level{_self, "active"_n});

        if (prod_itr == by_votes.end()){
                // testing purposes for unactivated chains
                requested.push_back(permission_level{"eosio"_n, "active"_n});
        }
        else {
                for (uint8_t i = 0;i<30;i++){
                        requested.push_back(permission_level{prod_itr->owner, "active"_n});
                        prod_itr++;
                }
        }

        action(permission_level{_self, "active"_n},
               "eosio.msig"_n, "propose"_n,
               std::make_tuple(
                       _self, // proposer
                       verification->claimer, // proposal name
                       requested,  // requested permissions
                       wrap  // transaction
               )).send();



        // Mark this verification as proposed
        verifications.modify(verification, same_payer, [&](verify_info &v){
            v.proposed = 1;
        });
}

void lostcontract::verify(std::vector<char> sig, name account, public_key newpubkey, name rampayer) {
        require_auth(rampayer);

        verifications_table verifications(_self, _self.value);
        whitelist_table whitelist(_self, _self.value);

        eosio_assert(is_account(account), "Account does not exist");

        // Disable for testing
//        auto whitelisted = whitelist.find(account.value);
//        eosio_assert(whitelisted != whitelist.end(), "Account is not whitelisted");

        auto verification = verifications.find(account.value);
        eosio_assert(verification == verifications.end(), "Account already verified");

        verifications.emplace(rampayer, [&](verify_info &v){
                v.claimer  = account;
                v.added    = time_point_sec(now());
                v.new_key  = newpubkey;
                v.proposed = 0;
        });
}

void lostcontract::reset(name claimer){
        require_auth(_self);

        verifications_table verifications(_self, _self.value);
        auto verification = verifications.find(claimer.value);

        eosio_assert(verification != verifications.end(), "Account not verified");

        verifications.modify(verification, same_payer, [&](verify_info &v){
            v.proposed = 0;
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


EOSIO_DISPATCH( lostcontract,
        (add)(propose)(verify)(reset)(clear)
)
