<?php

namespace PHPCrypto;

class Crypt
{
    protected $algo = 'aes-256-cbc';

    protected $iteration = 80000;

    protected $keySize = 32;

    protected $hashAlgo = 'sha256';

    protected $key;

    public function __construct(array $config = [])
    {
        $this->calcHmacSize($this->hashAlgo);
    }

    protected function calcHmacSize($hashAlgo)
    {
        $this->hmacSize = strlen(hash_hmac($hashAlgo, openssl_random_pseudo_bytes(32), $this->key, true));
    }

    public function setKey(string $key)
    {
        $this->key = $key;
    }

    public function getKey() : string
    {
        return $this->key;
    }

    /**
     * Encrypt-then-authenticate
     */
    public function encrypt(string $plaintext): string
    {
        if (empty($this->key)) {
            throw new \RuntimeException('The encryption key cannot be empty');
        }
        $ivSize = openssl_cipher_iv_length($this->algo);
        $iv     = random_bytes($ivSize);

        // Generate an encryption and authentication key
        $keys    = hash_pbkdf2($this->hashAlgo, $this->key, $iv, $this->iteration, $this->keySize * 2, true);
        $encKey  = substr($keys, 0, $this->keySize); // encryption key
        $hmacKey = substr($keys, $this->keySize);    // authentication key

        $ciphertext = openssl_encrypt(
            $plaintext,
            $this->algo,
            $encKey,
            OPENSSL_RAW_DATA,
            $iv
        );

        // authentication
        $hmac = hash_hmac($this->hashAlgo, $iv . $ciphertext, $hmacKey, true);
        return $hmac . $iv . $ciphertext;
    }

    public function decrypt(string $ciphertext): string
    {
        if (empty($this->key)) {
            throw new \RuntimeException('The decryption key cannot be empty');
        }
        $hmac       = substr($ciphertext, 0, $this->hmacSize);
        $ivSize     = openssl_cipher_iv_length($this->algo);
        $iv         = substr($ciphertext, $this->hmacSize, $ivSize);
        $ciphertext = substr($ciphertext, $ivSize + $this->hmacSize);

        // Generate the encryption and hmac keys
        $keys    = hash_pbkdf2($this->hashAlgo, $this->key, $iv, $this->iteration, $this->keySize * 2, true);
        $encKey  = substr($keys, 0, $this->keySize); // encryption key
        $hmacKey = substr($keys, $this->keySize);    // authentication key
        $hmacNew = hash_hmac($this->hashAlgo, $iv . $ciphertext, $hmacKey, true);
        if (!hash_equals($hmac, $hmacNew)) {
	         throw new \RuntimeException('Authentication failed');
        }
        return openssl_decrypt(
            $ciphertext,
            $this->algo,
            $encKey,
            OPENSSL_RAW_DATA,
            $iv
        );
    }
}
