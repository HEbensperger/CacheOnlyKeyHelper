#***************************************************************************#
# Author: Heinz Ebensperger                                                 #
# Usage: CacheOnlyCryptoHelper.py {certificate-file} {relative output-path} #
# This scrips helps to build the key cascade required to run a              #
# Salesforce Cache only environment.                                        #
#***************************************************************************#

from Crypto.Random       import get_random_bytes
from Crypto.Cipher       import AES, PKCS1_OAEP
from Crypto.PublicKey    import RSA
from Crypto.Protocol.KDF import scrypt
from pathlib             import Path

import OpenSSL.crypto
import string, os, sys, binascii, random, url64, uuid, json

# Open files 
try:
    path = sys.argv[2]
    os.mkdir(path)
except OSError:
    print("Creation of the directory %s failed" % path)
    print("Possible reason directory 'already exists', or you don't have 'required permissions'.")
    sys.exit("Please double check the aforemention and try again")

crt_in   = open(sys.argv[1], 'r')  # open the crt file...
jwe_out  = open(path + "/jweResponse", 'w') # create the output file file for jwe... 

def create_header(uuid): # Create the header information {"alg":"RSA--OAEP","enc":"A256GCM","kid":"46E3CD56-3880-4389-A6CB-38CCB22AC441"}
    header = '{"alg":"RSA--OAEP","enc":"A256GCM","kid":"' + str(uuid) + '"}'
    return header

def gen_key(type): # create the cek file and open for binary writing, generate the key and close the stream...
    key_out  = open(path + "/" + type + ".key", 'wb') 
    pwd = get_random_bytes(16)
    iv = get_random_bytes(32)  # Generate IV
    key = scrypt(pwd, iv, key_len=32, N=2**18, r=8, p=1)  # Generate a key using the password and IV
    print("Generated Key " + type + ":: " + str(key))
    key_out.write(key)
    key_out.close()
    return key

def read_key(index, type):
    key =  open(sys.argv[index], 'rb').read() # open and read the provided key file
    print("Used Key " + type + ":: " + str(key))
    return key

if(len(sys.argv)>=4): cek = read_key(3, 'cek')
else: cek = gen_key('cek')

if(len(sys.argv)>=5): dek = read_key(4, 'dek')
else: dek = gen_key('dek')

rsa = RSA.importKey(open(sys.argv[1]).read()) # import the public key from certificate
cek_cipher = PKCS1_OAEP.new(rsa)  # define the cipher
enc_cek = cek_cipher.encrypt(cek) # encrypt the cek with public key

dek_cipher = AES.new(cek, AES.MODE_GCM)  # Create a cipher object from cek in AES GCM Mode
enc_dek = dek_cipher.encrypt(dek) # encrypt the dek key with cek key
tag = dek_cipher.digest()  # Get the tag for decryption verification

uniq_uuid =  uuid.uuid4() # create a unique uuid

#build the deployable json
response_json = {}
response_json['kid'] = str(uniq_uuid)
response_json['jwe'] = url64.encode(create_header(uniq_uuid)) + "." + url64.encode(enc_cek) + "." + url64.encode(get_random_bytes(32)) + "." + url64.encode(enc_dek) +  "." + url64.encode(tag)
json_data = json.dumps(response_json)
jwe_out.write(json_data)

# Close all open files
crt_in.close()
jwe_out.close()