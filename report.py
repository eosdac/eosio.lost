#!/usr/bin/env python

import os
import sys
import json
import time
import struct
import requests as req
from hashlib import sha256
from bitcoin import ecdsa_raw_sign, encode_privkey
from tempfile import mktemp
from subprocess import Popen, PIPE
from sha3 import keccak_256
from getpass import getpass

API_URL = os.environ.get("API_URL", "http://127.0.0.1:8888")

def url_for(url):
  return '{0}{1}'.format(API_URL, url)

def endian_reverse_u32(x):
 x = x & 0xFFFFFFFF
 return (((x >> 0x18) & 0xFF)        )\
      | (((x >> 0x10) & 0xFF) << 0x08)\
      | (((x >> 0x08) & 0xFF) << 0x10)\
      | (((x        ) & 0xFF) << 0x18)

def is_canonical( sig ):
  return not (sig[1] & 0x80)\
     and not (sig[1] == 0 and not (sig[2] & 0x80))\
     and not (sig[33] & 0x80)\
     and not (sig[33] == 0 and not (sig[34] & 0x80))

def get_tapos_info(block_id):
  block_id_bin = block_id.decode('hex')

  hash0 = struct.unpack("<Q", block_id_bin[0:8])[0]
  hash1 = struct.unpack("<Q", block_id_bin[8:16])[0]

  ref_block_num  = endian_reverse_u32(hash0) & 0xFFFF
  ref_block_prefix = hash1 & 0xFFFFFFFF

  return ref_block_num, ref_block_prefix

if len(sys.argv) < 3:
  print "report.py EOSACCOUNT EOSPUBKEY PUSHER [ETHPRIV]"
  print "    EOSACCOUNT: Desired EOS account name"
  print "    EOSPUBKEY: Desired EOS pubkey"
  print "    PUSHER: account@permission used to sign and push the claim transaction"
  sys.exit(1)

eos_account  = sys.argv[1]
eos_pub      = sys.argv[2]
pusher       = sys.argv[3]
priv         = getpass("Enter ETH private key (Wif or Hex format)")

if '@' in pusher:
    rampayer = pusher.split('@')[0]
else:
    rampayer = pusher


while True:

    block_id = req.get(url_for('/v1/chain/get_info')).json()['last_irreversible_block_id']
    ref_block_num, ref_block_prefix = get_tapos_info(block_id)

    msg = "I lost my EOS genesis key and I request a key reset to %s" % eos_pub
    msghash = keccak_256(msg).digest()

    v, r, s = ecdsa_raw_sign(msghash, encode_privkey(priv,'hex').decode('hex'))
    signature = '00%02x%064x%064x' % (v,r,s)

print("Signature: {0}".format(signature))
if is_canonical(bytearray(signature.decode('hex'))):
    print("Signature is canonical")
else:
    print("Signature is not canonical")

action_args = json.dumps([
    signature,
    eos_account,
    eos_pub,
    eos_account
])
print(action_args)

with open(os.devnull, 'w') as devnull:
  cmd = ["cleos","-u", API_URL, "push", "action", "eosio.lost", "verify", action_args, "-p", pusher]
  p = Popen(cmd)
  output, err = p.communicate("")

if p.returncode:
  print "Error sending tx"
  sys.exit(1)

print "tx sent"
sys.exit(0)
