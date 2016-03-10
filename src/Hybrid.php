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
   *
   * Note: padding is set to OPENSSL_PKCS1_OAEP_PADDING to prevent
   * Bleichenbacher's chosen-ciphertext attack
   * @see http://crypto.stackexchange.com/questions/12688/can-you-explain-bleichenbachers-cca-attack-on-pkcs1-v1-5
   *
   * @param string $plaintext
   * @param string $publicKey
   * @param int $padding
   * @return string
   * @throws RuntimeException
   */
  public function encrypt(string $plaintext, string $publicKey, int $padding = OPENSSL_PKCS1_OAEP_PADDING) : string
  {
      // generate a random session key
      $sessionKey = random_bytes($this->symmetric->getKeySize());

      // encrypt the plaintext with symmetric algorithm
      $ciphertext = $this->symmetric->encrypt($plaintext, $sessionKey);

      // encrypt the session key with publicKey
      openssl_public_encrypt($sessionKey, $encryptedKey, $publicKey, $padding);

      return base64_encode($encryptedKey) . ':' . $ciphertext;
  }

  /**
   * Decrypt
   *
   * Note: padding is set to OPENSSL_PKCS1_OAEP_PADDING to prevent
   * Bleichenbacher's chosen-ciphertext attack
   * @see http://crypto.stackexchange.com/questions/12688/can-you-explain-bleichenbachers-cca-attack-on-pkcs1-v1-5
   *
   * @param string $msg
   * @param string $privateKey
   * @param int $padding
   * @return string
   * @throws RuntimeException
   */
  public function decrypt(string $msg, string $privateKey, int $padding = OPENSSL_PKCS1_OAEP_PADDING) : string
  {
      // get the session key
      list($encryptedKey, $ciphertext) = explode(':', $msg, 2);

      // decrypt the session key with privateKey
      openssl_private_decrypt(base64_decode($encryptedKey), $sessionKey, $privateKey, $padding);

      // encrypt the plaintext with symmetric algorithm
      return $this->symmetric->decrypt($ciphertext, $sessionKey);
  }
}
