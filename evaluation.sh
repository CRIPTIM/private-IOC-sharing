#!/bin/bash
# Copyright 2016 Tim van de Kamp. All rights reserved.
# Use of this source code is governed by the MIT license that can be
# found in the LICENSE file.
#
# Note: This script will run for some hours.
echo "cryptographic (HKDF)" > evaluation.dat
for i in {1..5}; do
	./match-rule.py --performance ./rules/rules/sample-hkdf-${i}.rule 2>/dev/null >> evaluation.dat
done
echo "cryptographic (PBKDF2)" >> evaluation.dat
for i in {1..5}; do
	./match-rule.py --performance ./rules/sample-pbkdf2-${i}.rule 2>/dev/null >> evaluation.dat
done
echo "plaintext" >> evaluation.dat
for i in {1..5};do
	./match-rule.py --performance --plaintext ./rules/sample-hkdf-${i}.rule 2>/dev/null >> evaluation.dat
done
