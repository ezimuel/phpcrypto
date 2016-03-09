<?php
/**
 * Hybrid encryption
 *
 * @author Enrico Zimuel (enrico@zimuel.it)
 */
declare(strict_types=1);

namespace PHPCrypto;

class Hybrid
{
  /**
   * Constructor
   * @param Symmetric $symmetric
   */
  public function __construct(Symmetric $symmetric)
  {
      $this->symmetric = $symmetric;
  }

  /**
   * Encrypt
   * @param string $plaintext
   * @param string $publicKey
   * @return string
   * @throws RuntimeException
   */
  public function encrypt(string $plaintext, string $publicKey) : string
  {
      // generate a random session key
      $sessionKey = random_bytes($this->symmetric->getKeySize());

      // encrypt the plaintext with symmetric algorithm
      $ciphertext = $this->symmetric->encrypt($plaintext, $sessionKey);

      // encrypt the session key with publicKey
      openssl_public_encrypt($sessionKey, $encryptedKey, $publicKey);

      return base64_encode($encryptedKey) . ':' . $ciphertext;
  }

  /**
   * Decrypt
   * @param string $msg
   * @param string $privateKey
   * @return string
   * @throws RuntimeException
   */
  public function decrypt(string $msg, string $privateKey) : string
  {
      // get the session key
      list($encryptedKey, $ciphertext) = explode(':', $msg, 2);

      // decrypt the session key with privateKey
      openssl_private_decrypt(base64_decode($encryptedKey), $sessionKey, $privateKey);

      // encrypt the plaintext with symmetric algorithm
      return $this->symmetric->decrypt($ciphertext, $sessionKey);
  }
}
