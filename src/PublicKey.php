<?php
/**
 * Public key encryption
 *
 * @author Enrico Zimuel (enrico@zimuel.it)
 */
declare(strict_types=1);

namespace PHPCrypto;

class PublicKey
{
    /**
     * Default value for OpenSSL public key
     */
    const DEFAULT_PUBLIC_KEY_OPTIONS = [
        "digest_alg"       => "sha512",
        "private_key_bits" => 4096,
        "private_key_type" => OPENSSL_KEYTYPE_RSA
    ];

    /**
     * @var string
     */
    protected $publicKey = '';

    /**
     * @var string
     */
    protected $privateKey = '';

    /**
     * Generate public and private key
     * @param array $options
     */
    public function generateKeys(array $options = self::DEFAULT_PUBLIC_KEY_OPTIONS)
    {
        $keys = openssl_pkey_new($options);
        $this->publicKey = openssl_pkey_get_details($keys)["key"];
        openssl_pkey_export($keys, $this->privateKey);
        openssl_pkey_free($keys);
    }

    /**
     * Get the public key
     * @return string
     */
    public function getPublicKey() : string
    {
        return $this->publicKey;
    }

    /**
     * Get the private key
     * @return string
     */
    public function getPrivateKey() : string
    {
        return $this->privateKey;
    }

    /**
     * Save the private key in a file using a passphrase
     * @param string $filename
     * @param string $passphrase
     * @return boolean
     */
    public function savePrivateKey(string $filename, string $passphrase)
    {
        return openssl_pkey_export_to_file ($this->getPrivateKey(), $filename, $passphrase);

    }

    /**
     * Read a private key from a file
     * @param string $filename
     * @param string $passphrase
     * @return string
     */
    public function readPrivateKey(string $filename, string $passphrase)
    {
        $result = openssl_pkey_get_private($filename, $passphrase);
        if (false === $result) {
            throw new \RuntimeException(
                sprintf("I cannot read the private key in %s", $filename)
            );
        }
        $this->privateKey = $result;
        return $this->privateKey;
    }

    /**
     * Save the public key in a file
     * @param string $filename
     */
    public function savePublicKey(string $filename)
    {
        file_put_contents($filename, $this->getPublicKey());
    }

    /**
     * Read the public key from a file
     * @param string $filename
     */
    public function readPublicKey(string $filename)
    {
        $this->publicKey = file_get_contents($filename);
        return $this->publicKey;
    }
}
