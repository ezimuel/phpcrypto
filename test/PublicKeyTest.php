<?php
declare(strict_types=1);

namespace PHPCryptoTest;

use PHPCrypto\PublicKey;

class PublicKeyTest extends \PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        $this->crypt = new PublicKey();
    }

    public function testSetPadding()
    {
        $padding = OPENSSL_SSLV23_PADDING;
        $this->crypt->setPadding($padding);
        $this->assertEquals($padding, $this->crypt->getPadding());
    }

    /**
     * @expectedException InvalidArgumentException
     */
    public function testSetInvalidPadding()
    {
        $padding = 1024;
        $this->crypt->setPadding($padding);
    }

    public function testGeneratePublicPrivateKeys()
    {
        $this->crypt->generateKeys([
            'private_key_bits' => 1024
        ]);
        $publicKey  = $this->crypt->getPublicKey();
        $privateKey = $this->crypt->getPrivateKey();

        $this->assertContains('-----BEGIN PUBLIC KEY-----', $publicKey);
        $this->assertContains('-----BEGIN PRIVATE KEY-----', $privateKey);

        return [
            'public'  => $publicKey,
            'private' => $privateKey
        ];
    }

    /**
     * @depends testGeneratePublicPrivateKeys
     */
    public function testEncryptDecrypt(array $keys)
    {
        $plaintext = random_bytes(64);
        $ciphertext = $this->crypt->encrypt($plaintext, $keys['public']);
        $result = $this->crypt->decrypt($ciphertext, $keys['private']);
        $this->assertEquals($plaintext, $result);
    }
}
