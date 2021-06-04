#********************************************************************************#
# Author: Heinz Ebensperger                                                      #
# Date: 06.03.2021                                                               #
#                                                                                #
# Usage: CacheOnlyCryptoHelper.py {certificate-file} {relative output-path}      #
#                                                                                #
# Optionally you can also provide the CEK and DEK if you have them already       #
# Usage:                                                                         #
# CacheOnlyCryptoHelper.py {certificate-file} {relative output-path} {cek} {dek} #
#                                                                                #
#                                                                                #
# Salesforce Cache only environment.                                             #
#********************************************************************************#

#from Crypto.Protocol.KDF import scrypt
from pathlib       import Path
from cryptography  import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers    import (Cipher, algorithms, modes)
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.asymmetric import (rsa, padding)

import string, os, sys, uuid, json, shutil, url64

# Open files 
path = sys.argv[2]
if os.path.exists(path) and os.path.isdir(path):
    print('Directory alreday exists, next step is deleting and recreating!')
    proceed = input('Do you want to proceed (y/N)') or 'N'
    if (proceed=='y' or proceed=='Y'):
        shutil.rmtree(path)
        os.mkdir(path)
    else:
        sys.exit()    
else:
    print('Creating directory!')
    os.mkdir(path)

crt   = open(sys.argv[1], 'rb').read()  # open the crt file...
jwe_out  = open(path + "/jweResponse", 'w') # create the output file file for jwe... 
#tag_out  = open(path + "/tag.out", 'wb') # file to store the tag for later verification
#nonce_out  = open(path + "/nonce.out", 'wb') # file to store the nonce for later verification

cert = x509.load_pem_x509_certificate(crt)
public_key = cert.public_key()
uniq_uuid =  uuid.uuid4() # create a unique uuid

def create_header(u_uuid): # Create the header information {"alg":"RSA--OAEP","enc":"A256GCM","kid":"46E3CD56-3880-4389-A6CB-38CCB22AC441"}
    header = '{"alg":"RSA-OAEP","enc":"A256GCM","kid":"' + str(u_uuid) + '"}'
    return header

def generate_key(type):
    key_out  = open(path + "/" + type + ".key", 'wb')     
    salt = os.urandom(16)
    pwd = os.urandom(32)
    kdf = Scrypt(salt=salt, length=32, n=2**18, r=8, p=1)
    key = kdf.derive(pwd)
    key_out.write(key)
    key_out.close()
    return key

def encrypt(key, plainkey):
    # Generate a random 96-bit IV.
    iv = os.urandom(12)
    # Construct an AES-GCM Cipher object with the given key and a randomly generated IV.
    encryptor = Cipher(algorithms.AES(key),modes.GCM(iv),).encryptor()
    # Encrypt the plaintext and get the associated ciphertext.
    encrypted_key = encryptor.update(plainkey) + encryptor.finalize()
    return (iv, encrypted_key, encryptor.tag)    

def read_key(index, type):
    key =  open(sys.argv[index], 'rb').read() # open and read the provided key file
    return key

if(len(sys.argv)>=4): cek = read_key(3, 'cek')
else: cek = generate_key('cek')

if(len(sys.argv)>=5): dek = read_key(4, 'dek')
else: dek = generate_key('dek')

enc_cek = public_key.encrypt(cek,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(),label=None))

nonce, enc_dek, tag = encrypt(cek, dek)

#build the deployable json
header = create_header(uniq_uuid).encode('utf-8')
response_string = url64.encode(header) + "." + url64.encode(enc_cek) + "." + url64.encode(nonce) + "." + url64.encode(enc_dek) +  "." + url64.encode(tag)
response_json = {}
response_json['kid'] = str(uniq_uuid)
response_json['jwe'] = str(response_string)

#write accomodating information
#tag_out.write(tag)
#nonce_out.write(nonce)

jwe_out.write(json.dumps(response_json)) #write the jwe response to file

# Close residial open files
jwe_out.close()
#tag_out.close()
#nonce_out.close()