# CacheOnlyKeyHelper

This Python script helps to generate a JWE Response Object for the Salesforce Platform Encryption CacheOnlyKey service. It's cryptographic functions are based on the cryptography Python module. 
Thus you need to have this module installed before running the script. 
The homepage for the module is here: https://cryptography.io/en/latest/. However, if you are just want to used the script, you might be most interested in the installation. 
Installation instructions to be found here: https://cryptography.io/en/latest/installation/


At a minimum you need to provide the already generated Certificate from your Salesforce Org and the path where the results should be written to.

The script either uses existing keys for CEK(Content Encryption Key) or DEK(Data Encryption Key), or generate it automatically within this script. 
Genration of keys depends on the arguments presented to the script.

Definition:
 * Arg 1 (Required): Name of the Certificate extracted from your Salesforce Org and the path where it's stored locally if not in the same directory as this script
 * Arg 2 (Required): Name of the directory where all produced artifacts will get stored, relativ to the current diretory
 * Arg 3 (Optional): Name and path to the CEK-Certificate 
 * Arg 3 (Optional): Name and path to the DEK-Certificate  

It's important to not mix up the two certificates, and when generated to safe them in a safe place. 
Data is lost when you loose the key that was used to encrypt the data.

Keys are generated using the KDF Scrypt from the Cryptograpy module (https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/#scrypt)
    
    `scrypt(pwd, iv, key_len=32, N=2**18, r=8, p=1)`

Strength of the keys and even runtime to generate the key depends on the Parameter `N=2**18`, which is good enough for testing purposes to be set between `14` (the default producing a good key) and `20` (a strong key).
