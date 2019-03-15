<h1 class="contract">updateauth</h1>

Input parameters:

* `claimer` (The name of the account requesting update)

Implied parameters:

* `signer` (The name of the account signing this action on behalf of `claimer`)

## Intent

By calling the action `updateauth`, I, {{ signer }}, wish to have the `owner` and `active` permissions of EOS account {{ claimer }} changed to the EOS public key provided previously using the `verify` action. The threshold of both permissions shall be set to `1`, and the EOS public key shall be given a weight of `1`. 

I, {{ signer }}, acknowledge that the keys cannot be changed unless a waiting period of at least 30 days has elapsed since the `verify` action was called, and that no transactions can have been authorized by the EOS account {{ claimer }} at any point. I acknowledge that any account can be used to call the `updateauth` action to authorize this action.


<h1 class="contract">verify</h1>

Input parameters:

* `sig` (Ethereum signed message)
* `account` (The EOS account requesting verification)
* `newpubkey` (The new EOS public key)
* `rampayer` (This account will have to store the verification data in their RAM)

Implied paramters:

* `signer` (The name of the account signing this action on behalf of `claimer`)

## Intent

As an authorized party, I {{ signer }}, have provided the Ethereum signature, {{ sig }}, associated with EOS account {{ account }} as per the genesis snapshot. I have confirmed that {{ account }} is listed on the unused genesis account list (also known as the whitelist) and has not authorized any transactions since genesis of the EOS mainnet of chain ID: aca376f206b8fc25a6ed44dbdc66547c36c6c33e3a119ffbeaef943642f0e906.

I, {{ signer }}, wish to submit the public key {{ newpubkey }}. The RAM required to store this information shall be paid for by my EOS account, {{ rampayer }}.

By calling the `verify` action, the 30-day waiting period shall be commenced, and this period must be satisfied before the `updateauth` action can be succesfully called, if and only if the checks of that action have been satisfied.

I, {{ signer }}, stipulate that I am, or have been authorized to take this action by the party submitting the cryptographic proof in the `sig` input parameter.
