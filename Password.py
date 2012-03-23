#!/usr/bin/env python

import math, string, sys
from Crypto.Hash import SHA256
from Crypto.Random import random

class Password:
    ALPHABETS = [
        string.ascii_lowercase,
        string.ascii_uppercase,
        string.digits,
        string.punctuation,
    ]

    def __init__(self, password, salt = None):
        self.password = password
        self.salt = salt
        if self.salt is None:
            self._generate_salt()

    def _generate_salt(self):
        possibilities = ''.join(self.ALPHABETS)
        self.salt = ''
        for i in range(15):
            self.salt += random.choice(possibilities)

    def generate_key(self):
        key = self.password + self.salt
        sha = SHA256.new()
        for i in range(999):
            sha.update(key)
            key = sha.digest()
        return key

    def is_strong(self):
        used = {}
        for alphabet in self.ALPHABETS:
            used[alphabet] = False
        for char in self.password:
            for alphabet in self.ALPHABETS:
                if char in alphabet:
                    used[alphabet] = True
        n = 0
        for alphabet in self.ALPHABETS:
            if used[alphabet]:
                n += len(alphabet)
        return len(self.password) * math.log(n, 2)

def new(password, salt = None):
    return Password(password, salt)



if __name__ == '__main__':
    weak_passwords = [
        'a',
        'asd',
        '123',
        'dupa',
        'ASD',
        'asdASD'
    ]
    for weak_password in weak_passwords:
        ent = Password(weak_password).is_strong()
        if ent < 50.0:
            print 'passed'
        else:
            print 'failed'

    strong_passwords = [
        'asdASDqwe123!@#,.asd123',
        '*&asdzxcAA123,czxq2314\\'
    ]
    for strong_password in strong_passwords:
        if Password(strong_password).is_strong():
            print 'passed'
        else:
            print 'failed'

    if Password('asd').generate_key():
        print 'passed'
    else:
        print 'failed'

    if Password('asd', 'asd').generate_key():
        print 'passed'
    else:
        print 'failed'
