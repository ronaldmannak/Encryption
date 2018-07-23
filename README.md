# Encryption
Playground RSA encryption and signing

Swift implementation of the RSA encryption algorithm, based on the description in [ArsTechnica](https://arstechnica.com/information-technology/2013/10/a-relatively-easy-to-understand-primer-on-elliptic-curve-cryptography/), for demo purposes.

##Known issues

- When randomly generating p, q and the public key, the generated private key becomes negative, causing encryption to fail.
- Integer overflows possible when using large p, q or max.
- There are likely many edge cases the code doesn't handle.