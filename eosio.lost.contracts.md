<h1 class="contract">updateauth</h1>

Input parameters:

* `claimer` (The name of the account requesting update)

## Intent

The intent of the `updateauth` action is to designate owner and active permissions to the recorded EOS public key associated with an EOS account, {{ claimer }}, registered on the `verified` database for longer than 30 days, so long as the public key provided in the genesis snapshot for the account {{ claimer }} has never signed a transaction.

As an authorized party, I {{ signer }}, wish to update owner and active permissions for EOS {{ claimer }} to the EOS public key provided previously in the `verify` action. 


<h1 class="contract">verify</h1>

Input parameters:

* `sig` (Ethereum signed message)
* `account` (The EOS account requesting verification)
* `newpubkey` (The new EOS public key)
* `rampayer` (This account will have to store the verification data in their RAM)

## Intent

The intent of the `verify` action is to record the EOS account name, verification date, and a new EOS public key selected by the party whose Ethereum key of the `sig` parameter matches the one linked to that EOS account, so long as the account is on the unused genesis account list. If there continues to be no activity on the recorded EOS account for the following 30 days, its owner and active key will be swapped with the new EOS public key using the `updateauth` action.

As an authorized party, I {{ signer }}, have provided the Ethereum signature: {{signature}} associated with EOS account: {{ account }} as per the genesis snapshot and have confirmed the EOS account is on the unused genesis account list and has no activity.

I wish to record the EOS public key {{ newpubkey }} and understand that anyone can call the `updateauth` action 30 days from the date of the block where the `verify` action is included, and, unless new transactions are authorized on EOS account, {{ account }}, within that time, the public key will be changed to the one provided. 

As signer, I stipulate that I am, or have been authorized to take this action by, the party submitting the cryptographic proof in the `sig` input parameter.
