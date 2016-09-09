# Copyright 2016 Tim van de Kamp. All rights reserved.
# Use of this source code is governed by the MIT license that can be
# found in the LICENSE file.
#
# Package HKDF is an implementation of the RFC 5869 “HMAC-based
# Extract-and-Expand Key Derivation Function (HKDF)”, which is used in
# evaluating a proof of concept implementation of cryptographic IOC
# matching as described in the paper “Private Sharing of IOCs and
# Sightings”.
import hmac
import hashlib

class HKDF:
    """
    Implementation of RFC 5869 "HMAC-based Extract-and-Expand Key
    Derivation Function (HKDF)".
    """
    def __init__(self, hash_name):
        self.hash_function = hashlib.new(hash_name)
        self.hash_name = hash_name

    def extract(self, salt=None, IKM=None):
        if salt is None:
            salt = b'\x00' * self.hash_function.digest_size
        self.extracted = hmac.new(salt, IKM, self.hash_name).digest()
        return self.extracted

    def expand(self, PRK=None, info=b'', L=None):
        if not PRK:
            PRK = self.extracted
        hash_len = self.hash_function.digest_size
        assert len(PRK) >= hash_len
        assert L <= 255 * hash_len

        N = L // hash_len + (0 if L % hash_len == 0 else 1)
        T_previous = b''
        T = b''
        for i in range(1, N+1):
            T_previous = hmac.new(PRK, T_previous + info + bytes([i]),
                    self.hash_name).digest()
            T += T_previous

        return T[:L]
