# CacheOnlyKeyHelper

This Python script helps to generate a JWE Response Object for the Salesforce Platform Encryption CacheOnlyKey service.

At a minimum you need to provide the already generated Certificate from your Salesforce Org and the path where the results should be written to.

The script either uses existing keys for CEK(Content Encryption Key) or DEK(Data Encryption Key), or generate it automatically within this script. 
Genration of keys depends on the arguments presented to the script.

Definition:
 * Arg 1 (Required): Name of the Certificate extracted from your Salesforce Org and the path where it's stored locally if not in the same directory as this script
 * Arg 2 (Required): Name of the directory where all produced artifacts will get stored, relativ to the current diretory
 * Arg 3 (Optional): Name and path to the CEK-Certificate 
 * Arg 3 (Optional): Name and path to the DEK-Certificate  

It's important to not mix up the two certificates, and when generated to safe them in a safe place. 
Data is lost when you loose the key used to initially encrypt the data.

Keys are generated with the scrypt method from the PyCryptodrome module (https://pycryptodome.readthedocs.io/en/latest/src/protocol/kdf.html#scrypt)
    `scrypt(pwd, iv, key_len=32, N=2**18, r=8, p=1)`
Strength of the keys and even runtime to generate the key depends on the Parameter `N=2**18`, which is good enough for testing purposes to be set between `17` (a good key) and `20` (a strong key).
