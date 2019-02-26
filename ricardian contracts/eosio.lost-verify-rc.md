## ACTION NAME : verify

### Description

The intent of the `verify` action is to record the EOS account name, verification date, and a new EOS public key selected by the party whose Ethereum key of {{signature}} matches the one linked to that EOS account, so long as the account is on the unused genesis account list and has no activity. If there continues to be no activity on the recorded EOS account for the following 30 days, its owner and active key will be swapped with the new EOS public key using the `updateauth` action.

As an authorized party, I {{ signer }}, have provided the Ethereum signature: {{signature}} associated with EOS account: {{ account }} as per the genesis snapshot and have confirmed the EOS account is on the unused genesis account list and has no activity.

I wish to record the EOS public key {{ eos_pubkey_str }} and understand that anyone can call the updateauth action 30 days from {{ date }}, and, unless new transactions are authorized on EOS account, {{ account }}, within that time, the public key will be changed to the one provided. 

As signer, I stipulate that I am, or have been authorized to take this action by, the party submitting the cryptographic proof {{signature}}.
