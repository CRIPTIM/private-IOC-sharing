#!/usr/bin/env python3
# Copyright 2016 Tim van de Kamp. All rights reserved.
# Use of this source code is governed by the MIT license that can be
# found in the LICENSE file.
import argparse
import configparser
import glob
import hashlib
import re
import subprocess
import sys
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util import Counter
from hkdf import hkdf

parser = argparse.ArgumentParser(description='Create an encrypted IOC \
        rule.')
parser.add_argument('attribute', nargs='+', help='key-value attribute')
parser.add_argument('message', help='course of action to take when IOC \
        matches')
parser.add_argument('-f', '--filename', help='output file name to store \
        the encrypted IOC')
parser.add_argument('--hash', dest='hash_name', default='sha256',
        help='hash function to use')
parser.add_argument('--iterations', type=int, default=1,
        help='iterations needed before the decryption key is derived')
parser.add_argument('--plaintext', action='store_true',
        help='store the plaintext rule as well')

args = parser.parse_args()

# Set options
if args.filename:
    IOC_id = args.filename
else:
    IOC_id = 'unknown'
salt = Random.new().read(hashlib.new(args.hash_name).digest_size)
dklen = 16 # AES block size
attributes = dict(pair.split("=") for pair in args.attribute)
iv = Random.new().read(16)
password = ','.join(value for (key, value) in attributes.items())
attributes = ','.join(key for (key, value) in attributes.items())

# Encrypt the associated message
if args.iterations == 1:
    kdf = hkdf.HKDF(args.hash_name)
    kdf.extract(salt, password.encode('ascii'))
    dk = kdf.expand(info=IOC_id.encode('ascii'), L=dklen)
else:
    dk = hashlib.pbkdf2_hmac(args.hash_name, password.encode('ascii'), salt, args.iterations, dklen=dklen)
ctr = Counter.new(128, initial_value=int.from_bytes(iv, 'big'))
cipher = AES.new(dk, AES.MODE_CTR, b'', counter=ctr)
ciphertext = cipher.encrypt(b'\x00'*16 + args.message.encode('utf-8'))

# Store in rule file
rule = configparser.ConfigParser()
if args.iterations == 1:
    rule['hkdf'] = {}
    rule['hkdf']['hash_name'] = args.hash_name
    rule['hkdf']['salt'] = b64encode(salt).decode('ascii')
    rule['hkdf']['dklen'] = str(dklen)
else:
    rule['pbkdf2'] = {}
    rule['pbkdf2']['hash_name'] = args.hash_name
    rule['pbkdf2']['salt'] = b64encode(salt).decode('ascii')
    rule['pbkdf2']['iterations'] = str(args.iterations)
    rule['pbkdf2']['dklen'] = str(dklen)
rule['ioc'] = {}
rule['ioc']['id'] = IOC_id
rule['ioc']['attributes'] = attributes
rule['ioc']['iv'] = b64encode(iv).decode('ascii')
rule['ioc']['ciphertext'] = b64encode(ciphertext).decode('ascii')
if args.plaintext:
    rule['ioc']['dk'] = b64encode(dk).decode('ascii')
    rule['ioc']['plaintext'] = password
    rule['ioc']['coa'] = args.message

if args.filename:
    with open(args.filename, 'w') as configfile:
        rule.write(configfile)
else:
    print(rule._sections)
