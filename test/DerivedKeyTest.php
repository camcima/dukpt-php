<?php

require_once __DIR__ . '/../src/DerivedKey.php';
require_once __DIR__ . '/../src/KeySerialNumber.php';

class DerivedKeyTest extends PHPUnit_Framework_TestCase
{
    public function testDeriveFirstKey()
    {
        $bdk = '0123456789ABCDEFFEDCBA9876543210';
        $ksn = 'FFFF9876543210E00001';

        $ksnObj = new KeySerialNumber($ksn);
        $key = DerivedKey::calculateDerivedKey($ksnObj, $bdk);

        $this->assertEquals('042666B49184CFA368DE9628D0397BC9', $key);
    }

    public function testDeriveSecondKey()
    {
        $bdk = '0123456789ABCDEFFEDCBA9876543210';
        $ksn = 'FFFF9876543210E00002';

        $ksnObj = new KeySerialNumber($ksn);
        $key = DerivedKey::calculateDerivedKey($ksnObj, $bdk);

        $this->assertEquals('C46551CEF9FD24B0AA9AD834130D3BC7', $key);
    }

    public function testCalculateFirstEncryptionKey()
    {
        $bdk = '0123456789ABCDEFFEDCBA9876543210';
        $ksn = 'FFFF9876543210E00001';

        $ksnObj = new KeySerialNumber($ksn);
        $key = DerivedKey::calculateDataEncryptionRequestKey($ksnObj, $bdk);

        $this->assertEquals('448D3F076D8304036A55A3D7E0055A78', $key);
    }

    public function testCalculateSecondEncryptionKey()
    {
        $bdk = '0123456789ABCDEFFEDCBA9876543210';
        $ksn = 'FFFF9876543210E00002';

        $ksnObj = new KeySerialNumber($ksn);
        $key = DerivedKey::calculateDataEncryptionRequestKey($ksnObj, $bdk);

        $this->assertEquals('F1BE73B36135C5C26CF937D50ABBE5AF', $key);
    }

    public function testCalculateLastEncryptionKey()
    {
        $bdk = '0123456789ABCDEFFEDCBA9876543210';
        $ksn = 'FFFF9876543210E00015';

        $ksnObj = new KeySerialNumber($ksn);
        $key = DerivedKey::calculateDataEncryptionRequestKey($ksnObj, $bdk);

        $this->assertEquals('D9AE3E62F5E3CA2C357E37F500D9F314', $key);
    }

    public function testCalculateEncryptionKeyForReal()
    {
        $ksn = '62994901190000000002';
        $bdk = '0123456789ABCDEFFEDCBA9876543210';

        $key = new KeySerialNumber($ksn);
        $encryptionKey = DerivedKey::calculateDataEncryptionRequestKey($key, $bdk);

        $this->assertEquals('1A994C3E09D9ACEF3EA9BD4381EFA334', $encryptionKey);
    }

    public function testDecryptDukptMessage()
    {
        $encryptedHexData = 'DA7F2A52BD3F6DD8B96C50FC39C7E6AF22F06ED1F033BE0FB23D6BD33DC5A1F808512F7AE18D47A60CC3F4559B1B093563BE7E07459072ABF8FAAB5338C6CC8815FF87797AE3A7BE';
        $ksn = '62994901190000000002';
        $bdk = '0123456789ABCDEFFEDCBA9876543210';

        $key = new KeySerialNumber($ksn);
        $encryptionKey = DerivedKey::calculateDataEncryptionRequestKey($key, $bdk);
        $actual = Utility::hex2bin(Utility::tripleDesDecrypt($encryptedHexData, $encryptionKey));
        $expected = '';

        $this->assertEquals($expected, $actual);
    }

}
