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
     * Valid padding mode for encryption/decryption
     */
    const VALID_PADDINGS = [
        OPENSSL_PKCS1_PADDING,
        OPENSSL_SSLV23_PADDING,
        OPENSSL_PKCS1_OAEP_PADDING,
        OPENSSL_NO_PADDING
    ];

    /**
     * @var int
     * Note: padding is set to OPENSSL_PKCS1_OAEP_PADDING to prevent
     * Bleichenbacher's chosen-ciphertext attack
     * @see http://crypto.stackexchange.com/questions/12688/can-you-explain-bleichenbachers-cca-attack-on-pkcs1-v1-5
     *
     */
    protected $padding = OPENSSL_PKCS1_OAEP_PADDING;

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
     * Set a padding for encryption/decryption mode
     * @param int $padding
     * @throws InvalidArgumentException
     */
    public function setPadding(int $padding)
    {
        if (! in_array($padding, self::VALID_PADDINGS)) {
            throw new \InvalidArgumentException(
                sprintf("The padding specified %d is not supported", $padding)
            );
        }
        $this->padding = $padding;
    }

    /**
     * Get the padding value
     * @return int
     */
    public function getPadding(): int
    {
        return $this->padding;
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
     * @throws RuntimeException
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

    /**
     * Encrypt a string using a public key
     * @param string $plaintext
     * @param string $publicKey
     * @return string
     * @throws RuntimeException
     */
    public function encrypt(string $plaintext, string $publicKey = '') : string
    {
        if (empty($publicKey)) {
            if (empty($this->publicKey)) {
                throw new \RuntimeException(
                    "I cannot encrypt without a public key"
                );
            }
            $publicKey = $this->publicKey;
        }
        if (! openssl_public_encrypt($plaintext, $result, $publicKey, $this->padding)) {
            throw new \RuntimeException(
                sprintf("Error during encrypt: %s", openssl_error_string())
            );
        }
        return $result;
    }

    /**
     * Decrypt using a private key
     * @param string $ciphertext
     * @param string $privateKey
     * @return string
     * @throws RuntimeException
     */
    public function decrypt(string $ciphertext, string $privateKey = '') : string
    {
        if (empty($privateKey)) {
            if (empty($this->privateKey)) {
                throw new \RuntimeException(
                    "I cannot decrypt without a private key"
                );
            }
            $privateKey = $this->privateKey;
        }
        if (! openssl_private_decrypt($ciphertext, $result, $privateKey, $this->padding)) {
            throw new \RuntimeException(
                sprintf("Error during decrypt: %s", openssl_error_string())
            );
        }
        return $result;
    }
}
