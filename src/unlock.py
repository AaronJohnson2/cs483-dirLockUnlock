#Students: Hayden Coffey, Aaron Johnson
#COSC 483, Project 3
"""
The below program is used for unlocking a
given locked directory using appropriate certificates
"""
from halib3_max_takes_manhattan import arg_return, decrypt_file
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


if __name__ == "__main__":
    #Parse cmd line arguments
    argv = arg_return(sys.argv, 1)
    rootDir = argv.d
    publicKey = argv.p
    privateKey = argv.r
    subject = argv.s

    #Open certificate files
    publicFile = open(publicKey, 'rb')
    privateFile = open(privateKey, 'rb')

    #Verify subject
    if subject != publicFile.readline().decode("utf-8").rstrip():
        print("Error: Public File, Non-matching subjects")
        exit(1)

    if subject != privateFile.readline().decode("utf-8").rstrip():
        pass

    #Verify algorithms
    if 'ec' != publicFile.readline().rstrip().decode("utf-8"):
        print("Error: Incorrect public certificate, EC required.")
        exit(1)

    if 'rsa' != privateFile.readline().rstrip().decode("utf-8"):
        print("Error: Incorrect private certificate, RSA required.")
        exit(1)

    #Read in certificate keys
    tmpPubKey = ''
    for line in publicFile:
        tmpPubKey += line.decode("utf-8")

    tmpPrivKey = ''
    for line in privateFile:
        tmpPrivKey += line.decode("utf-8")

    #Read in AES key and signature
    with open(rootDir+'/keyfile', 'rb') as file:
        keyFile = file.read()

    with open(rootDir+'/keyfile.sig', 'rb') as file:
        sigFile = file.read()

    #Verify signature
    pubKey = ECC.import_key(tmpPubKey)
    cipherVerify = DSS.new(pubKey, 'fips-186-3')
    try:
        cipherVerify.verify(SHA256.new(keyFile), sigFile)
    except ValueError:
        print("Keyfile signature is not authentic.")
        exit(1)

    #Delete keyfile and signature
    os.remove(rootDir+'/keyfile')
    os.remove(rootDir+'/keyfile.sig')

    #Decrypt AES key
    privKey = RSA.import_key(tmpPrivKey)
    oepCipher = PKCS1_OAEP.new(privKey)
    key = oepCipher.decrypt(keyFile)

    #Decrypt directory
    for dirName, subdirlist, filelist in os.walk(rootDir):
        for file in filelist:
            decrypt_file(key, dirName+'/'+file)

    publicFile.close()
    privateFile.close()
