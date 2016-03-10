<?php
/**
 * Symmetric encryption + authentication
 * encrypt-then-authenticate with HMAC
 * Default: AES in CBC + HMAC-SHA256
 *
 * @author Enrico Zimuel (enrico@zimuel.it)
 */
declare(strict_types=1);

namespace PHPCrypto;

class Symmetric
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
     * Symmetric encryption key
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
        return mb_strlen(hash_hmac($hash, 'test', openssl_random_pseudo_bytes(32), true), '8bit');
    }

    /**
     * Set the encryption key
     * @param string $key
     */
    public function setKey(string $key)
    {
        $this->checkLengthKey($key);
        $this->key = $key;
    }

    /**
     * Check the key length for security reason
     * @param string
     */
    protected function checkLengthKey($key)
    {
        if (mb_strlen($key, '8bit') < self::MIN_SIZE_KEY) {
            trigger_error(
                sprintf("The encryption key %s it's too short!", $key),
                E_USER_WARNING
            );
        }
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
     * Set the encryption key size (in bytes)
     * @param int $size
     */
    public function setKeySize(int $size)
    {
        if ($size < 16) { // key size < 128 bits
            trigger_error(
                sprintf("The size %d of the encryption key it's too short!", $size),
                E_USER_WARNING
            );
        }
        $this->keySize = $size;
    }

    /**
     * Get the key size of the cipher (in bytes)
     * @return int
     */
    public function getKeySize() : int
    {
        return $this->keySize;
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
     * @param string $key
     * @return string
     * @throws \RuntimeException
     */
    public function encrypt(string $plaintext, string $key = '') : string
    {
        if (empty($key) && empty($this->key)) {
            throw new \RuntimeException('The encryption key cannot be empty');
        }
        if (empty($key)) {
          $key = $this->key;
        } else {
          $this->checkLengthKey($key);
        }

        $ivSize = openssl_cipher_iv_length($this->algo);
        $iv     = random_bytes($ivSize);

        // Generate an encryption and authentication key
        $keys    = hash_pbkdf2($this->hash, $key, $iv, $this->iterations, $this->keySize * 2, true);
        $encKey  = mb_substr($keys, 0, $this->keySize, '8bit'); // encryption key
        $hmacKey = mb_substr($keys, $this->keySize, null, '8bit');    // authentication key

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
     * @param string $key
     * @return string
     * @throws \RuntimeException
     */
    public function decrypt(string $ciphertext, string $key = '') : string
    {
        if (empty($key) && empty($this->key)) {
            throw new \RuntimeException('The decryption key cannot be empty');
        }
        if (empty($key)) {
          $key = $this->key;
        } else {
          $this->checkLengthKey($key);
        }
        $hmac       = mb_substr($ciphertext, 0, $this->hmacSize, '8bit');
        $ivSize     = openssl_cipher_iv_length($this->algo);
        $iv         = mb_substr($ciphertext, $this->hmacSize, $ivSize, '8bit');
        $ciphertext = mb_substr($ciphertext, $ivSize + $this->hmacSize, null, '8bit');

        // Generate the encryption and hmac keys
        $keys    = hash_pbkdf2($this->hash, $key, $iv, $this->iterations, $this->keySize * 2, true);
        $encKey  = mb_substr($keys, 0, $this->keySize, '8bit'); // encryption key
        $hmacKey = mb_substr($keys, $this->keySize, null, '8bit');    // authentication key

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
