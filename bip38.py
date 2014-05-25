#!/usr/bin/python
# -*- coding: utf8 -*-

#
# (C) by nomorecoin (https://github.com/nomorecoin)
# (C) by Romano Kleinwächter (https://github.com/rkl-)
#
# USAGE: Just run the script, enter by copy paste your unencrypted private key,
#        e.g. from vanitygen, enter then your password and you get the encrypted
#        version of your key. This is usefull for cold storage and the Mycelium
#        android wallet.
#

from Crypto.Cipher import AES
import scrypt
import hashlib
from pybitcointools import *
import binascii
import base58
import getpass
import sys

def bip38_encrypt(privkey,passphrase):
    '''BIP0038 non-ec-multiply encryption. Returns BIP0038 encrypted privkey.'''
    privformat = get_privkey_format(privkey)
    if privformat in ['wif_compressed','hex_compressed']:
        compressed = True
        flagbyte = '\xe0'
        if privformat == 'wif_compressed':
            privkey = encode_privkey(privkey,'hex_compressed')
            privformat = get_privkey_format(privkey)
    if privformat in ['wif', 'hex']:
        compressed = False
        flagbyte = '\xc0'
    if privformat == 'wif':
        privkey = encode_privkey(privkey,'hex')
        privformat = get_privkey_format(privkey)
    pubkey = privtopub(privkey)
    addr = pubtoaddr(pubkey)
    addresshash = hashlib.sha256(hashlib.sha256(addr).digest()).digest()[0:4]
    key = scrypt.hash(passphrase, addresshash, 16384, 8, 8)
    derivedhalf1 = key[0:32]
    derivedhalf2 = key[32:64]
    aes = AES.new(derivedhalf2)
    encryptedhalf1 = aes.encrypt(binascii.unhexlify('%0.32x' % (long(privkey[0:32], 16) ^ long(binascii.hexlify(derivedhalf1[0:16]), 16))))
    encryptedhalf2 = aes.encrypt(binascii.unhexlify('%0.32x' % (long(privkey[32:64], 16) ^ long(binascii.hexlify(derivedhalf1[16:32]), 16))))
    encrypted_privkey = ('\x01\x42' + flagbyte + addresshash + encryptedhalf1 + encryptedhalf2)
    encrypted_privkey += hashlib.sha256(hashlib.sha256(encrypted_privkey).digest()).digest()[:4] # b58check for encrypted privkey
    encrypted_privkey = base58.b58encode(encrypted_privkey)
    return encrypted_privkey

def bip38_decrypt(encrypted_privkey,passphrase):
    '''BIP0038 non-ec-multiply decryption. Returns WIF privkey.'''
    d = base58.b58decode(encrypted_privkey)
    d = d[2:]
    flagbyte = d[0:1]
    d = d[1:]
    if flagbyte == '\xc0':
        compressed = False
    if flagbyte == '\xe0':
        compressed = True
    addresshash = d[0:4]
    d = d[4:-4]
    key = scrypt.hash(passphrase,addresshash, 16384, 8, 8)
    derivedhalf1 = key[0:32]
    derivedhalf2 = key[32:64]
    encryptedhalf1 = d[0:16]
    encryptedhalf2 = d[16:32]
    aes = AES.new(derivedhalf2)
    decryptedhalf2 = aes.decrypt(encryptedhalf2)
    decryptedhalf1 = aes.decrypt(encryptedhalf1)
    priv = decryptedhalf1 + decryptedhalf2
    priv = binascii.unhexlify('%064x' % (long(binascii.hexlify(priv), 16) ^ long(binascii.hexlify(derivedhalf1), 16)))
    pub = privtopub(priv)
    if compressed:
        pub = encode_pubkey(pub,'hex_compressed')
        wif = encode_privkey(priv,'wif_compressed')
    else:
        wif = encode_privkey(priv,'wif')
    addr = pubtoaddr(pub)
    if hashlib.sha256(hashlib.sha256(addr).digest()).digest()[0:4] != addresshash:
        print('Addresshash verification failed! Password is likely incorrect.')
    return wif

pkey = getpass.getpass(prompt='Privkey: ')
pass1 = getpass.getpass(prompt='Password: ')
pass2 = getpass.getpass(prompt='Retype password: ')
if pass2 != pass1:
	print >> sys.stderr, 'Password did not match!'
	sys.exit(-1)
	
print bip38_encrypt(pkey, pass1)

