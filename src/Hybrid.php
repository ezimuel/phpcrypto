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
   * @var Symmetric
   */
  protected $symmetric;

  /**
   * @var PublicKey
   */
  protected $public;

  /**
   * Constructor
   *
   * @param Symmetric $symmetric
   * @param PublicKey $public
   */
  public function __construct(Symmetric $symmetric = null, PublicKey $public = null)
  {
      $this->symmetric = (null === $symmetric) ? new Symmetric() : $symmetric;
      $this->public    = (null === $public ) ? new PublicKey() : $public;
  }

  /**
   * Encrypt
   *
   * @param string $plaintext
   * @param string $publicKey
   * @return string
   * @throws RuntimeException
   */
  public function encrypt(string $plaintext, string $publicKey = '') : string
  {
      // generate a random session key
      $sessionKey = random_bytes($this->symmetric->getKeySize());

      // encrypt the plaintext with symmetric algorithm
      $ciphertext = $this->symmetric->encrypt($plaintext, $sessionKey);

      // encrypt the session key with publicKey
      $encryptedKey = $this->public->encrypt($sessionKey, $publicKey);

      // openssl_public_encrypt($sessionKey, $encryptedKey, $publicKey, $padding);

      return base64_encode($encryptedKey) . ':' . $ciphertext;
  }

  /**
   * Decrypt
   *
   * @param string $msg
   * @param string $privateKey
   * @return string
   * @throws RuntimeException
   */
  public function decrypt(string $msg, string $privateKey = '') : string
  {
      // get the session key
      list($encryptedKey, $ciphertext) = explode(':', $msg, 2);

      // decrypt the session key with privateKey
      $sessionKey = $this->public->decrypt(base64_decode($encryptedKey), $privateKey);
      //openssl_private_decrypt(base64_decode($encryptedKey), $sessionKey, $privateKey, $padding);

      // encrypt the plaintext with symmetric algorithm
      return $this->symmetric->decrypt($ciphertext, $sessionKey);
  }

  /**
   * Get the Symmetric adapter
   *
   * @return Symmetric
   */
  public function getSymmetricInstance()
  {
      return $this->symmetric;
  }

  /**
   * Get the Public Key adapter
   *
   * @return PublicKey
   */
  public function getPublicKeyInstance()
  {
      return $this->public;
  }
}
