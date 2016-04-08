<?php
declare(strict_types=1);

namespace PHPCryptoTest;

use PHPCrypto\Hybrid;
use PHPCrypto\Symmetric;
use PHPCrypto\PublicKey;

class HybridTest extends \PHPUnit_Framework_TestCase
{
    public function setup()
    {
        $this->crypt = new Hybrid();
    }

    public function testConstructor()
    {
        $crypt = new Hybrid();

        $this->assertInstanceOf(Hybrid::class, $crypt);
        $this->assertInstanceOf(Symmetric::class, $crypt->getSymmetricInstance());
        $this->assertInstanceOf(PublicKey::class, $crypt->getPublicKeyInstance());
    }

    public function testConstructorWithParams()
    {
        $symmetric = new Symmetric();
        $publicKey = new PublicKey();
        $crypt     = new Hybrid($symmetric, $publicKey);

        $this->assertInstanceOf(Hybrid::class, $crypt);
        $this->assertEquals($symmetric, $crypt->getSymmetricInstance());
        $this->assertEquals($publicKey, $crypt->getPublicKeyInstance());
    }

    public function getKeys()
    {
        return [
            [
                '-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDA6FXJn00TOAMH8tFweQ+TCd8T
Rxa7R28KH8p9VVzYVXeHyYZIgX2QObaJBH7NZtmLQ9TJyiTMOfcz56vKwll7cLzY
RxqLh6aIqXwvJXdRutVqJWwZ4qBGMc6/z+Scda8HSI0j9Mv381cGxWsIMToRCx/y
Eg2v+JIJXGY5DE75YQIDAQAB
-----END PUBLIC KEY-----',
                '-----BEGIN PRIVATE KEY-----
MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAMDoVcmfTRM4Awfy
0XB5D5MJ3xNHFrtHbwofyn1VXNhVd4fJhkiBfZA5tokEfs1m2YtD1MnKJMw59zPn
q8rCWXtwvNhHGouHpoipfC8ld1G61WolbBnioEYxzr/P5Jx1rwdIjSP0y/fzVwbF
awgxOhELH/ISDa/4kglcZjkMTvlhAgMBAAECgYA+W5xHpcAjg0qvihWb1vZq4JkE
wUke1vOVATvSkgKGR/JwqXtH+tvdAFr6JcLboPCXrSCe7kJA5kf7tlr5GyQTS249
CeWJmgch9fjOPVqTnLoi7d/7KxkCKRocSNm8PfXI5BCYJcfJMAVWCJqFSqSJd4wY
2jP8J4LBjp3U+kTJAQJBAPn4bmwxDDKEZ2LgGOQjpPPivMmxdvOTUAGLUFyqiAIm
VsX5gPgreA3SmlxlAvgji8FzfC4PbxAIM2T/vDKr6DECQQDFj4pMkUQT6C/utp7y
nR87uyGO4b1ll75Y0Go684tZhEfXD/RbKTsOZCV6Tx4vxfSFKygaJMXpQ7k2ydXZ
BggxAkAFisF/+pJnqFHWelty62tj0NoYqquVeOWkMx+D/m/nhEwWNZLrbaNKwymS
9NZdBAS8NEBDkSoIM/ZXvefBQ9hxAkArmgJr46OiwRvTE3sBEKxUAnjlj+y8/0CD
WXwYhqe6mfdA/8RuWisugevDkrKW2JmeymePXY5QbSHzdZg8zZgBAkEAsuVxxZVi
ax6azz9Ve3/bSxP77ikE1pjbh4dLgAhMuoDeUCUxT0zD2ALEpnci84Vf3DmzZkkB
mtfQDL3hqbP7kg==
-----END PRIVATE KEY-----'
            ]
        ];
    }

    /**
     * @dataProvider getKeys
     */
    public function testHybridEncryptionWithExplicitKeys($publicKey, $privateKey)
    {
        $plaintext  = random_bytes(4096);
        $ciphertext = $this->crypt->encrypt($plaintext, $publicKey);

        $this->assertEquals(
            $plaintext,
            $this->crypt->decrypt($ciphertext, $privateKey)
        );
    }

}
