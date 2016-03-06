<?php
/**
 * Crypto class to encrypt/decrypt string using encrypt-then-authenticate
 * technique with HMAC
 *
 * @author Enrico Zimuel (enrico@zimuel.it)
 */
declare(strict_types=1);

namespace PHPCrypto;

class Crypt
{
    /**
     * Minimum number of PBKDF2 iteration allowed for security reason
     * @see http://goo.gl/OzdRxi
     */
    const MIN_PBKDF2_ITERATIONS = 20000;

    /**
     * Minimum size of key in bytes
     * @see https://en.wikipedia.org/wiki/Password_strength
     */
    const MIN_SIZE_KEY = 12;

    /**
     * @var string
     */
    protected $algo = 'aes-256-cbc';

    /**
     * Set the default number of iteration 4x the min value
     * @see https://goo.gl/bzv4dK
     * @var int
     */
    protected $iterations = self::MIN_PBKDF2_ITERATIONS * 4;

    /**
     * @var string
     */
    protected $hash = 'sha256';

    /**
     * @var string
     */
    protected $key;

    /**
     * @var int
     */
    private $hmacSize = 32; // SHA-256

    /**
     * @var int
     */
    private $keySize = 32;

    /**
     * Constructor
     */
    public function __construct(array $config = [])
    {
        if (!empty($config)) {
          if (isset($config['algo'])) {
              $this->setAlgorithm($config['algo']);
          }
          if (isset($config['hash'])) {
              $this->setHash($config['hash']);
          }
          if (isset($config['iterations'])) {
              $this->setIterations($config['iterations']);
          }
          if (isset($config['key'])) {
              $this->setKey($config['key']);
          }
        }
    }

    /**
     * Calc the output size of hash_hmac
     * @return int
     */
    protected function getHmacSize($hash) : int
    {
        return strlen(hash_hmac($hash, 'test', openssl_random_pseudo_bytes(32), true));
    }

    /**
     * Set the encryption key
     * @param string $key
     */
    public function setKey(string $key)
    {
        if (strlen($key) < self::MIN_SIZE_KEY) {
            trigger_error(
                sprintf("The encryption key %s it's too short!", $key),
                E_USER_WARNING
            );
        }
        $this->key = $key;
    }

    /**
     * Get the encryption key
     * @return string
     */
    public function getKey(): string
    {
        return $this->key;
    }

    /**
     * Set the symmetric encryption algorithm
     * @param string $algo
     * @throws \InvalidArgumentException
     */
    public function setAlgorithm(string $algo)
    {
        if (!in_array($algo, openssl_get_cipher_methods(true))) {
            throw new \InvalidArgumentException(sprintf(
                "The algorithm %s is not supported by OpenSSL", $algo
            ));
        }
        $this->algo = $algo;
    }

    /**
     * Get the symmetric encryption algorithm
     * @return string
     */
    public function getAlgorithm() : string
    {
        return $this->algo;
    }

    /**
     * Set the hash algorithm for PBKDF2 and HMAC
     * @param string $hash
     * @throws \InvalidArgumentException
     */
    public function setHash(string $hash)
    {
        if (!in_array($hash, hash_algos())) {
            throw new \InvalidArgumentException(sprintf(
                "The hash algorithm %s is not supported", $hash
            ));
        }
        $this->hash     = $hash;
        $this->hmacSize = $this->getHmacSize($this->hash);
    }

    /**
     * Get the hash algorithm used by PBKDF2 and HMAC
     * @return string
     */
    public function getHash() : string
    {
        return $this->hash;
    }

    /**
     * Set the number of iteration for PBKDF2
     * @param int $iteration
     */
    public function setIterations(int $iterations)
    {
        // Security warning
        if ($iterations < self::MIN_PBKDF2_ITERATIONS) {
            trigger_error(
                sprintf("The number of iteration %s used for PBKDF2 it's too low!", $iterations),
                E_USER_WARNING
            );
        }
        $this->iterations = $iterations;
    }

    /**
     * Get the number of iterations for PBKDF2
     * @return int
     */
    public function getIterations() : int
    {
        return $this->iterations;
    }

    /**
     * Encrypt-then-authenticate with HMAC
     * @param string $plaintext
     * @return string
     * @throws \RuntimeException
     */
    public function encrypt(string $plaintext) : string
    {
        if (empty($this->key)) {
            throw new \RuntimeException('The encryption key cannot be empty');
        }
        $ivSize = openssl_cipher_iv_length($this->algo);
        $iv     = random_bytes($ivSize);

        // Generate an encryption and authentication key
        $keys    = hash_pbkdf2($this->hash, $this->key, $iv, $this->iterations, $this->keySize * 2, true);
        $encKey  = substr($keys, 0, $this->keySize); // encryption key
        $hmacKey = substr($keys, $this->keySize);    // authentication key

        // Encrypt
        $ciphertext = openssl_encrypt(
            $plaintext,
            $this->algo,
            $encKey,
            OPENSSL_RAW_DATA,
            $iv
        );
        // Authentication
        $hmac = hash_hmac($this->hash, $iv . $ciphertext, $hmacKey, true);
        return $hmac . $iv . $ciphertext;
    }

    /**
     * Authenticate-then-decrypt with HMAC
     * @param string $ciphertext
     * @return string
     * @throws \RuntimeException
     */
    public function decrypt(string $ciphertext) : string
    {
        if (empty($this->key)) {
            throw new \RuntimeException('The decryption key cannot be empty');
        }
        $hmac       = substr($ciphertext, 0, $this->hmacSize);
        $ivSize     = openssl_cipher_iv_length($this->algo);
        $iv         = substr($ciphertext, $this->hmacSize, $ivSize);
        $ciphertext = substr($ciphertext, $ivSize + $this->hmacSize);

        // Generate the encryption and hmac keys
        $keys    = hash_pbkdf2($this->hash, $this->key, $iv, $this->iterations, $this->keySize * 2, true);
        $encKey  = substr($keys, 0, $this->keySize); // encryption key
        $hmacKey = substr($keys, $this->keySize);    // authentication key

        // Authentication
        $hmacNew = hash_hmac($this->hash, $iv . $ciphertext, $hmacKey, true);
        if (!hash_equals($hmac, $hmacNew)) {
	         throw new \RuntimeException('Authentication failed');
        }
        // Decrypt
        return openssl_decrypt(
            $ciphertext,
            $this->algo,
            $encKey,
            OPENSSL_RAW_DATA,
            $iv
        );
    }
}
