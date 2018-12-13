#Students: Hayden Coffey, Aaron Johnson
#COSC 483, Project 3
"""
The below program is used for generating RSA/EC
Keys and Certificates for public/private pairs
"""
from halib3_max_takes_manhattan import arg_return
import sys
from Crypto.PublicKey import RSA, ECC

if __name__ == "__main__":
    #Parse cmd line argumens
    argv = arg_return(sys.argv, 0)
    subject = argv.s
    publicType = argv.t
    publicFile = argv.pub
    privateFile = argv.priv

    #Open certificate files
    publicFile = open(publicFile, 'wb')
    privateFile = open(privateFile, 'wb')

    #Write subject and algorithm type
    publicFile.write((subject+'\n').encode())
    publicFile.write((publicType+'\n').encode())

    privateFile.write((subject+'\n').encode())
    privateFile.write((publicType+'\n').encode())

    #Generate either RSA or EC public/private pair and write to certificate
    if publicType == 'rsa':
        keyPrivate = RSA.generate(2048)
        keyPublic = keyPrivate.publickey()  # e = 65537, FIPS default
        publicFile.write(keyPublic.export_key(format='PEM'))
        privateFile.write(keyPrivate.export_key(format='PEM'))

    elif publicType == 'ec':
        keyPrivate = ECC.generate(curve='P-256')
        keyPublic = keyPrivate.public_key()
        publicFile.write(keyPublic.export_key(format='PEM').encode())
        privateFile.write(keyPrivate.export_key(format='PEM').encode())

    else:
        print("Error", publicType, "not recognized.")
