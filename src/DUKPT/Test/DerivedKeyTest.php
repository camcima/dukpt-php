<?php

namespace DUKPT\Test;

use DUKPT\DerivedKey;
use DUKPT\KeySerialNumber;
use DUKPT\Utility;

class DerivedKeyTest extends AbstractTest
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

    public function testDecryptDukptTrack1()
    {
        $encryptedHexData = 'DA7F2A52BD3F6DD8B96C50FC39C7E6AF22F06ED1F033BE0FB23D6BD33DC5A1F808512F7AE18D47A60CC3F4559B1B093563BE7E07459072ABF8FAAB5338C6CC8815FF87797AE3A7BE';
        $ksn = '62994901190000000002';
        $bdk = '0123456789ABCDEFFEDCBA9876543210';

        $key = new KeySerialNumber($ksn);
        $encryptionKey = DerivedKey::calculateDataEncryptionRequestKey($key, $bdk);
        $actual = Utility::hex2bin(Utility::removePadding(Utility::tripleDesDecrypt($encryptedHexData, $encryptionKey, true)));
        $expected = '%B4266841088889999^BUSH JR/GEORGE W.MR^0809101100001100000000046000000?!';

        $this->assertEquals($expected, $actual);
    }

    public function testDecryptDukptTrack2()
    {
        $encryptedHexData = 'AB3B10A3FBC230FBFB941FAC9E82649981AE79F2632156E775A06AEDAFAF6F0A184318C5209E55AD';
        $ksn = '62994901190000000002';
        $bdk = '0123456789ABCDEFFEDCBA9876543210';
        
        $key = new KeySerialNumber($ksn);
        $encryptionKey = DerivedKey::calculateDataEncryptionRequestKey($key, $bdk);
        $actual = Utility::hex2bin(Utility::removePadding(Utility::tripleDesDecrypt($encryptedHexData, $encryptionKey, true)));

        $expected = ";4266841088889999=080910110000046?0";

        $this->assertEquals($expected, $actual);
    }
    
}
