#Students: Hayden Coffey, Aaron Johnson
#COSC 483, Project 3
"""
Hayden -> H, Aaron -> A: Its a library,
Its the Hayden/Aaron Library, HALIB!
All of our beloved functions(army) reside here
"""
import argparse
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA, ECC
from Crypto.Signature import DSS
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
import sys
import os
import json
import base64


def arg_return(argv, mode):
    """
    Parse cmdline arguments, mode=0 for keygen,
    mode=1 for lock/unlock
    """
    if not mode:
        parser = argparse.ArgumentParser(
            description='Generate public/private key pair.')
        parser.add_argument('-t', help="rsa/ec")
        parser.add_argument('-s', help="subject")
        parser.add_argument('-pub', help="Public key file.")
        parser.add_argument('-priv', help="Private key file.")

        if len(argv) == 1:
            parser.print_help()
            exit()

        args = parser.parse_args()

        return args
    else:
        parser = argparse.ArgumentParser(
            description='Lock/unlock given directory.')
        parser.add_argument('-d', help="Directory to unlock/lock")
        parser.add_argument('-p', help="Action public key")
        parser.add_argument('-r', help="Action private key")
        parser.add_argument('-s', help="Action subject")

        if len(argv) == 1:
            parser.print_help()
            exit()

        args = parser.parse_args()

        return args


def encrypt_file(key, fileName):
    """
    Encrypts given file with given key
    using AES-GCM
    """
    with open(fileName, 'rb') as file:
        cipher = AES.new(key, AES.MODE_GCM)
        data = file.read()
        c, t = cipher.encrypt_and_digest(data)

        with open(fileName, 'wb') as outfile:
            jval = json.dumps({'nonce': base64.b64encode(cipher.nonce).decode(
                'utf-8'), 'cipherText': base64.b64encode(c).decode('utf-8'), 'mac': base64.b64encode(t).decode('utf-8')})
            outfile.write(jval.encode())


def decrypt_file(key, fileName):
    """
    Decrypts given file with given
    key using AES-GCM
    """
    with open(fileName, 'r') as file:
        try:
            jval = json.load(file)
            cipher = AES.new(key, AES.MODE_GCM,
                             nonce=base64.b64decode(jval['nonce']))
            plaintext = cipher.decrypt_and_verify(base64.b64decode(
                jval['cipherText']), base64.b64decode(jval['mac']))

            with open(fileName, 'wb') as outfile:
                outfile.write(plaintext)

        except ValueError:
            print(fileName, "was not authentic!")
            exit(1)
