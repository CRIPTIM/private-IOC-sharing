#!/usr/bin/env python3
# Copyright 2016 Tim van de Kamp. All rights reserved.
# Use of this source code is governed by the MIT license that can be
# found in the LICENSE file.
import argparse
import configparser
import glob
import hashlib
import os
import re
import subprocess
import sys
from base64 import b64decode
from copy import deepcopy
from Crypto.Cipher import AES
from Crypto.Util import Counter
from functools import lru_cache
from hkdf import hkdf

parser = argparse.ArgumentParser(description='Evaluate a network dump against rules.')
parser.add_argument('rule', nargs='+',
        help='rule file or directory containing rules to evaluate (rules \
        must end in .rule)')
parser.add_argument('--bro', dest='bro_bin', default='/usr/bin/bro',
        help='path to the Bro binary')
parser.add_argument('--dump', dest='tcpdump', default='outside.tcpdump',
        help='path to the tcpdump to analyze')
parser.add_argument('--performance', action='store_true',
        help='run a performance test')
parser.add_argument('--plaintext', action='store_true',
        help='evaluate on the plaintext rules instead of cryptographic \
                rules')

args = parser.parse_args()

def load_rule(filename):
    ruleParser = configparser.ConfigParser()
    ruleParser.read(filename)
    rule = ruleParser._sections
    try:
        rule['iterations'] = 1
        rule['hash_name'] = rule['hkdf']['hash_name']
        rule['salt'] = b64decode(rule['hkdf']['salt'])
        rule['dklen'] = int(rule['hkdf']['dklen'])
    except:
        try:
            rule['iterations'] = int(rule['pbkdf2']['iterations'])
            rule['hash_name'] = rule['pbkdf2']['hash_name']
            rule['salt'] = b64decode(rule['pbkdf2']['salt'])
            rule['dklen'] = int(rule['pbkdf2']['dklen'])
        except:
            raise Exception('Not a rule file.')
    rule['ioc']['attributes'] = rule['ioc']['attributes'].split(',')
    rule['ioc']['iv'] = int.from_bytes(b64decode(rule['ioc']['iv']), 'big')
    rule['ioc']['ciphertext'] = b64decode(rule['ioc']['ciphertext'])
    return rule

def derive_key(hash_name, password, salt, iterations, info, dklen=None):
    if iterations == 1:
        kdf = hkdf.HKDF(hash_name)
        return kdf.expand(kdf.extract(salt, password), info.encode('ascii'), dklen)
    else:
        return hashlib.pbkdf2_hmac(hash_name, password, salt, iterations, dklen=dklen)

#@lru_cache(maxsize=None)
def cryptographic_match(hash_name, password, salt, iterations, info, dklen, iv, ciphertext):
    dk = derive_key(hash_name, password.encode('ascii'), salt, iterations, info, dklen=dklen)

    ctr = Counter.new(128, initial_value=iv)
    cipher = AES.new(dk, AES.MODE_CTR, b'', counter=ctr)
    # A match is found when the first block is all null bytes
    if cipher.decrypt(ciphertext[:16]) == b'\x00'*16:
        plaintext = cipher.decrypt(ciphertext[16:])
        return (True, plaintext)
    else:
        return (False, '')

def cryptographic_matching(pipe):
    for line in pipe.stdout:
        # Remove trailing newline
        attributes = line[:-1].decode("ascii")
        # Remove bracets
        attributes = attributes[1:-1]
        # Parse attributes as a dictionary
        attributes = dict(pair.split("=") for pair in attribute_split.split(attributes))
        for rule in rules:
            password = ','.join([attributes[selected_attribute] for selected_attribute in rule['ioc']['attributes']])

            # Actual cryptographic matching
            match, plaintext = cryptographic_match(rule['hash_name'], password, rule['salt'], rule['iterations'], rule['ioc']['id'], rule['dklen'], rule['ioc']['iv'], rule['ioc']['ciphertext'])
            if match and not args.performance:
                print("IOC '{}' matched for: {}\nCourse of Action\n================\n{}\n".format(rule['ioc']['id'], attributes, plaintext.decode('utf-8')))

def plaintext_matching(pipe):
    for line in pipe.stdout:
        # Remove trailing newline
        attributes = line[:-1].decode("ascii")
        # Remove bracets
        attributes = attributes[1:-1]
        # Parse attributes as a dictionary
        attributes = dict(pair.split("=") for pair in attribute_split.split(attributes))
        for rule in rules:
            password = ','.join([attributes[selected_attribute] for selected_attribute in rule['ioc']['attributes']])

            # Actual plaintext matching
            if rule['ioc']['plaintext'] == password and not args.performance:
                print("IOC '{}' matched for: {}\nCourse of Action\n================\n{}\n".format(rule['ioc']['id'], attributes, rule['ioc']['coa']))

# Performance test settings
if args.performance:
    import timeit
    number_of_runs = 5
    number_of_experiments = 100

if __name__ == "__main__":
    rules = list()
    for rule_location in args.rule:
        if os.path.isfile(rule_location):
            rules.append(deepcopy(load_rule(rule_location)))
        elif os.path.isdir(rule_location):
            rule_directory = os.path.normpath(rule_location + "/")
            for filename in glob.glob(os.path.join(rule_directory, "*.rule")):
                rules.append(deepcopy(load_rule(filename)))

    if not rules:
        sys.exit("No rules found.")

    bro = subprocess.Popen([args.bro_bin, '-b', '-r', args.tcpdump, 'connection.bro'], stdout=subprocess.PIPE)
    attribute_split = re.compile(', id=\[|\], |, ')

    if args.plaintext:
        if args.performance:
            print(timeit.repeat("pipe = subprocess.Popen([args.bro_bin, '-b', '-r', args.tcpdump, 'connection.bro'], stdout=subprocess.PIPE);plaintext_matching(pipe)",
                repeat=number_of_runs, number=number_of_experiments,
                globals=globals()))
        else:
            plaintext_matching(bro)
    else:
        if args.performance:
            print(timeit.repeat("pipe = subprocess.Popen([args.bro_bin, '-b', '-r', args.tcpdump, 'connection.bro'], stdout=subprocess.PIPE);cryptographic_matching(pipe)",
                repeat=number_of_runs, number=number_of_experiments,
                globals=globals()))
            #print(cryptographic_match.cache_info(), file=sys.stderr)
        else:
            cryptographic_matching(bro)
