<?php
declare(strict_types=1);

namespace PHPCryptoTest;

use PHPCrypto\Symmetric;

class SymmetricTest extends \PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        $this->crypt = new Symmetric();
        $this->crypt->setIterations(Symmetric::MIN_PBKDF2_ITERATIONS);
    }

    public function testConstructor()
    {
        $crypt = new Symmetric();
        $this->assertInstanceOf(Symmetric::class, $crypt);
    }

    public function testConstructWithOptions()
    {
        $algos = openssl_get_cipher_methods(true);
        $algo = $algos[array_rand($algos)];
        $hash = hash_algos()[array_rand(hash_algos())];
        $iterations = Symmetric::MIN_PBKDF2_ITERATIONS * 3;

        $options = [
            'algo'       => $algo,
            'hash'       => $hash,
            'iterations' => $iterations
        ];
        $crypt = new Symmetric($options);
        $this->assertInstanceOf(Symmetric::class, $crypt);
        $this->assertEquals($algo, $crypt->getAlgorithm());
        $this->assertEquals($hash, $crypt->getHash());
        $this->assertEquals($iterations, $crypt->getIterations());
    }

    public function testSetKey()
    {
        $key = random_bytes(Symmetric::MIN_SIZE_KEY);
        $this->crypt->setKey($key);
        $this->assertEquals($key, $this->crypt->getKey());
    }

    /**
     * @expectedException PHPUnit_Framework_Error_Warning
     */
    public function testSetShortKey()
    {
        $this->crypt->setKey('test');
    }

    public function testSetKeySize()
    {
        $size = 24;
        $this->crypt->setKeySize($size);
        $this->assertEquals($size, $this->crypt->getKeySize());
    }

    /**
     * @expectedException PHPUnit_Framework_Error_Warning
     */
    public function testSetKeySizeTooShort()
    {
        $size = 8;
        $this->crypt->setKeySize($size);
    }

    public function testSetIterations()
    {
        $iterations = Symmetric::MIN_PBKDF2_ITERATIONS * 2;
        $this->crypt->setIterations($iterations);
        $this->assertEquals($iterations, $this->crypt->getIterations());
    }

    /**
     * @expectedException PHPUnit_Framework_Error_Warning
     */
    public function testSetLowNumberOfIterations()
    {
        $this->crypt->setIterations(1);
    }

    public function testSetAlgorithm()
    {
        $algos = openssl_get_cipher_methods(true);
        $algo = $algos[array_rand($algos)];
        $this->crypt->setAlgorithm($algo);
        $this->assertEquals($algo, $this->crypt->getAlgorithm());
    }

    /**
     * @expectedException InvalidArgumentException
     */
    public function testSetUndefinedAlgorithm()
    {
        $this->crypt->setAlgorithm('foo');
    }

    public function testSetHash()
    {
        $hash = hash_algos()[array_rand(hash_algos())];
        $this->crypt->setHash($hash);
        $this->assertEquals($hash, $this->crypt->getHash());
    }

    /**
     * @expectedException InvalidArgumentException
     */
    public function testSetUndefinedHash()
    {
        $this->crypt->setHash('foo');
    }

    public function testEncryptDecrypt()
    {
        $this->crypt->setKey(random_bytes(Symmetric::MIN_SIZE_KEY));
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
        $this->crypt->setKey(random_bytes(Symmetric::MIN_SIZE_KEY));
        $plaintext = random_bytes(1024);

        $ciphertext = $this->crypt->encrypt($plaintext);
        // alter the $ciphertext
        $ciphertext = substr($ciphertext, 0, -1);
        $result = $this->crypt->decrypt($ciphertext);
    }
}
