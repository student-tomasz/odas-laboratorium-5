#!/usr/bin/env python

import fileinput, math, string, sys
from Crypto.Cipher import AES
import Password

class MyFile:
    def __fill_plain_data(self, data, multiple):
        data += ' ' * (((len(data) / multiple) + 1) * multiple - len(data))
        return data

    def __entropy(self, data):
        bytes = {}
        for byte in data:
            if not byte in bytes:
                bytes[byte] = 0
            bytes[byte] += 1
        for byte in bytes:
            bytes[byte] = float(bytes[byte]) / float(len(data))
        entropy = 0
        for byte in bytes:
            entropy -= bytes[byte] * math.log(bytes[byte], 2)
        return entropy

    def encrypt(self, password, plain_path, encrypted_path = None):
        plain_file = open(plain_path, 'rb')
        if encrypted_path is None:
            encrypted_path = plain_path + '.encrypted'
        encrypted_file = open(encrypted_path, 'wb')

        password = Password.new(password)
        aes = AES.new(password.generate_key())

        plain_data = self.__fill_plain_data(plain_file.read(), aes.block_size)
        encrypted_file.write(password.salt + '\n')
        encrypted_file.write(aes.encrypt(plain_data))

        for opened_file in [encrypted_file, plain_file]:
            opened_file.close()

    def decrypt(self, password, encrypted_path, plain_path = None):
        encrypted_file = open(encrypted_path, 'rb')
        if plain_path is None:
            plain_path = encrypted_path + '.plain'
        plain_file = open(plain_path, 'wb')

        salt = encrypted_file.readline().strip()
        password = Password.new(password, salt)
        aes = AES.new(password.generate_key())

        encrypted_data = encrypted_file.read()
        plain_file.write(aes.decrypt(encrypted_data))

        for opened_file in [encrypted_file, plain_file]:
            opened_file.close()

    def bruteforce(self, encrypted_path, bruteforced_path = None):
        encrypted_file = open(encrypted_path, 'rb')
        if bruteforced_path is None:
            bruteforced_path = encrypted_path + '.bruteforced'
        bruteforced_file = open(bruteforced_path, 'wb')

        bruteforced = {}
        bruteforced_entropies = {}

        salt = encrypted_file.readline().strip()
        encrypted = encrypted_file.read()

        passwords = []
        for first in string.ascii_lowercase:
            for second in string.ascii_lowercase:
                passwords.append(first+second)
        # print 'debug: generated passwords'

        for password in passwords:
            # print 'debug: going over password \'{}\''.format(password)
            aes = AES.new(Password.new(password, salt).generate_key())
            decrypted = aes.decrypt(encrypted)
            bruteforced[password] = decrypted
            bruteforced_entropies[password] = self.__entropy(decrypted)
        # print 'debug: bruteforced file for all passwords'

        best_password = min(bruteforced_entropies, key = bruteforced_entropies.get)
        # print 'debug: found best password'
        print 'log: best password is \'{}\''.format(best_password)
        bruteforced_file.write(bruteforced[best_password])

        for opened_file in [encrypted_file, bruteforced_file]:
            opened_file.close()



if __name__ == '__main__':
    my_file = MyFile()
    if len(sys.argv) >= 4:
        command = sys.argv[1]
        password = sys.argv[2]
        source_path = sys.argv[3]
        target_path = None
        if len(sys.argv) > 4:
            target_path = sys.argv[4]
        if hasattr(my_file, command):
            getattr(my_file, command)(password, source_path, target_path)
    else:
        password = 'asd'
        source_path = 'samples/lorem.txt'
        plain_path = source_path + '.plain'
        encrypted_path = source_path + '.encrypted'
        my_file.encrypt(password, source_path, encrypted_path)
        my_file.decrypt(password, encrypted_path, plain_path)
        if (open(source_path).read().strip() == open(plain_path).read().strip()):
            print 'passed'
        else:
            print 'failed'

        password = 'ab'
        source_path = 'samples/lorem.txt'
        encrypted_path = source_path + '.encrypted'
        bruteforced_path = source_path + '.bruteforced'
        my_file.encrypt(password, source_path, encrypted_path)
        my_file.bruteforce(encrypted_path, bruteforced_path)
        if (open(source_path, 'rb').read().strip() == open(bruteforced_path, 'rb').read().strip()):
            print 'passed'
        else:
            print 'failed'
