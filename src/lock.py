#Students: Hayden Coffey, Aaron Johnson
#COSC 483, Project 3
"""
The below program is used for locking a
given directory using appropriate certificates
"""
from halib3_max_takes_manhattan import arg_return, encrypt_file
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
    if 'rsa' != publicFile.readline().rstrip().decode("utf-8"):
        print("Error: Incorrect public certificate, RSA required.")
        exit(1)

    if 'ec' != privateFile.readline().rstrip().decode("utf-8"):
        print("Error: Incorrect private certificate, EC required.")
        exit(1)

    #Read in certificate keys
    tmpPubKey = ''
    for line in publicFile:
        tmpPubKey += line.decode("utf-8")

    tmpPrivKey = ''
    for line in privateFile:
        tmpPrivKey += line.decode("utf-8")

    #Generate and encrypt AES key via RSA
    rsaPubKey = RSA.import_key(tmpPubKey)
    rsaCipher = PKCS1_OAEP.new(rsaPubKey)

    key = get_random_bytes(32)
    cipherText = rsaCipher.encrypt(key)

    #Sign encrypted AES key
    ecPrivKey = ECC.import_key(tmpPrivKey)
    ecSigner = DSS.new(ecPrivKey, 'fips-186-3')
    cipherSig = ecSigner.sign(SHA256.new(cipherText))

    #Encrypt directory
    for dirName, subdirlist, filelist in os.walk(rootDir):
        for file in filelist:
            encrypt_file(key, dirName+'/'+file)

    #Write keyfile and signature to files
    keyfile = open(rootDir+'/keyfile', 'wb')
    sigfile = open(rootDir+"/keyfile.sig", 'wb')
    keyfile.write(cipherText)
    sigfile.write(cipherSig)

    publicFile.close()
    privateFile.close()
    keyfile.close()
    sigfile.close()
