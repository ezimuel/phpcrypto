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
}
