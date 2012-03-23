#!/usr/bin/env python

import fileinput, string, sys
from Crypto.Cipher import AES
import Password

class MyFile:
    def __fill_plain_data(self, data, multiple):
        data += ' ' * (((len(data) / multiple) + 1) * multiple - len(data))
        return data

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



if __name__ == '__main__':
    my_file = MyFile()
    command = sys.argv[1]
    if len(sys.argv) > 2:
        password = sys.argv[2]
        source_path = sys.argv[3]
    target_path = None
    if len(sys.argv) > 4:
        target_path = sys.argv[4]

    if hasattr(my_file, command):
        getattr(my_file, command)(password, source_path, target_path)
    elif command == 'test':
        password = 'asd'
        source_path = 'sample/sample.txt'
        plain_path = source_path + '.plain'
        encrypted_path = plain_path + '.encrypted'
        my_file.encrypt('asd', source_path, encrypted_path)
        my_file.decrypt('asd', encrypted_path, plain_path)
        if (open(source_path).read().strip() == open(plain_path).read().strip()):
            print 'passed'
        else:
            print 'failed'
