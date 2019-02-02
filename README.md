# EOSIO Lost Key Recovery Contract

The purpose of this contract is to allow EOS account holders to reset their genesis key because the registered key was lost or incorrectly generated.

## Requirements for key reset

- **The account which is having the key reset is a genesis EOS account** and has a corresponding Ethereum address.
- **The user must be able to provide a signed message indicating that they want their key changed.**  This means they must still have control of their Ethereum private key, which can be using a private key file or a hardware wallet such as Ledger or Trezor.
- **There must have been no activity on the EOS account**, if any actions have been signed by the 'lost' key then the reset request will be rejected.
- **Only one reset will be allowed per account.**  Once you have reset the keys, the account will be marked and no further recoveries will be permitted.
- **The account holder must wait 30 days before the keys are reset following the verification.**  The account being modified will be sent a message indicating that their account is due for reset, during the 30 day period the key holder can make a transaction on the account to block the key change.
- **Your Ethereum account must not show clear signs of being attacked and drained.** We will run scripts designed to detect hacked Ethereum accounts and remove them from the whitelist.

## Procedure

- The user signs a specially formatted Ethereum message, most likely using a user interface provided
- The contract will verify that the signature is valid and that there has been no activity on the account, if these tests pass then the account will be added to the verified table.
- The account will be sent a message in multiple languages alerting the holder that someone has requested that their keys will be reset.
- 30 days after the successful verification of of the signature, the account will be eligible to be updated.
- Anyone may then call the `updateauth` action which will again verify that there has been no activity on the account.
- The active and owner keys will then be automatically updated.

