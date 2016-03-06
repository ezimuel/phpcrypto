<?php
namespace PHPCryptoTest;

use PHPCrypto\Crypt;

class CryptTest extends \PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        $this->crypt = new Crypt();
    }

    public function testSetKey()
    {
        $this->crypt->setKey('test');
        $this->assertEquals('test', $this->crypt->getKey());
    }

    public function testEncryptDecrypt()
    {
        $this->crypt->setKey('test');
        $plaintext = random_bytes(1024);

        $ciphertext = $this->crypt->encrypt($plaintext);
        $this->assertEquals($plaintext, $this->crypt->decrypt($ciphertext));
    }

    /**
     * @expectedException RuntimeException
     * @expectedExceptionMessage The encryption key cannot be empty
     */
    public function testEncryptWithEmptyKey()
    {
        $plaintext = random_bytes(1024);
        $ciphertext = $this->crypt->encrypt($plaintext);
    }

    /**
     * @expectedException RuntimeException
     * @expectedExceptionMessage The decryption key cannot be empty
     */
    public function testDecryptWithEmptyKey()
    {
        $ciphertext = random_bytes(1024);
        $result = $this->crypt->decrypt($ciphertext);
    }

    /**
     * @expectedException RuntimeException
     * @expectedExceptionMessage Authentication failed
     */
    public function testAuthenticationFailure()
    {
        $this->crypt->setKey('test');
        $plaintext = random_bytes(1024);

        $ciphertext = $this->crypt->encrypt($plaintext);
        // alter the $ciphertext
        $ciphertext = substr($ciphertext, 0, -1);
        $result = $this->crypt->decrypt($ciphertext);
    }
}
