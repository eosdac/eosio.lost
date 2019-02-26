## ACTION NAME : updateauth

### Description

The intent of the `updateauth` action is to designate owner and active permissions to the recorded EOS public key {{ eos_pubkey_str }} on the associated EOS account, {{ account }}, registered on the `verify` database for longer than 30 days, so long as {{ account }} has never authorized a transaction.

As an authorized party, I {{ signer }}, wish to update owner and active permissions for EOS {{account}} to EOS public key {{ eos_pubkey_str }}. 
