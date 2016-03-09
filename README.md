# PHPCrypto

[![Build Status](https://secure.travis-ci.org/ezimuel/phpcrypto.svg?branch=master)](https://secure.travis-ci.org/ezimuel/phpcrypto)


## About

This is a cryptography library for PHP 7. It's based on [OpenSSL](http://php.net/manual/en/book.openssl.php) and provides the following features:

- Symmetric encryption and authentication (AES + HMAC-SHA256 as default);
- Public Key cryptography (management keys, encryption/decryption)
- Hybrid encryption using symmetric and public key ([OpenPGP](http://www.ietf.org/rfc/rfc4880.txt) like)

## Version

As this software is **ALPHA, Use at your own risk!**

## Usage

The usage is quite straightforward, after installing the library using composer:

```
composer install
```

You can consume the following classes Symmetric, PublicKey and Hybrid for
symmetric encryption, public key and hybrid encryption.

For instance, if you want to encrypt a string in a symmetric way, you can use
the following code:

```php
use PHPCrypto\Symmetric;

$plaintext = 'Text to encrypt';
$key = '123456789012'; // This can be also a user's password we generate a new
                       // one for encryption using PBKDF2 algorithm

$cipher = new Symmetric(); // AES + HMAC-SHA256 by default
$cipher->setKey($key);
$ciphertext = $cipher->encrypt($plaintext);

// or passing the $key as optional paramter
// $ciphertext = $cipher->encrypt($plaintext, $key);

$result = $cipher->decrypt($ciphertext);

// or passing the $key as optional paramter
// $result = $cipher->decrypt($ciphertext, $key);

print ($result === $plaintext) ? "OK" : "FAILURE";
```

## TO DO

- encrypt/decrypt functions in PublicKey
- sign/verify functions for digital signature in PublicKey
- Ca management in public key schemas

## NOTES ABOUT OPENSSL EXTENSION

Here I reported some notes about the OpenSSL PHP extension usage:

- it will be nice to have the **openssl_cipher_key_size()** function to get the
  key size of the specific cipher choosen;


## Copyright

Copyright 2016 by [Enrico Zimuel](http://www.zimuel.it)

The license usage is reported in the [LICENSE](license) file.
