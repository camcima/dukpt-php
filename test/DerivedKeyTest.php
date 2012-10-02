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

        $this->assertEquals('448D3F076D8304036A55A3D7E0055A78', $key);
    }

    public function testDeriveSecondKey()
    {
        $bdk = '0123456789ABCDEFFEDCBA9876543210';
        $ksn = 'FFFF9876543210E00002';

        $ksnObj = new KeySerialNumber($ksn);
        $key = DerivedKey::calculateDerivedKey($ksnObj, $bdk);

        $this->assertEquals('448D3F076D8304036A55A3D7E0055A78', $key);
    }
    
    public function testCalculateDerivedKey()
    {
        $ksn = "FFFF9876543210E00001";
        $key = new KeySerialNumber($ksn);
        $bdk = "0123456789ABCDEFFEDCBA9876543210";
        $actual = DerivedKey::calculateDerivedKey($key, $bdk);
        $expected = "DC3170007A69CD6EDDF55E6B21E73855";

        $this->assertEquals($expected, $actual);
    }
    
    public function testCalculateDerivedKeyForReal() {
        $encryptedData = Utility::hex2bin('DA7F2A52BD3F6DD8B96C50FC39C7E6AF22F06ED1F033BE0FB23D6BD33DC5A1F808512F7AE18D47A60CC3F4559B1B093563BE7E07459072ABF8FAAB5338C6CC8815FF87797AE3A7BE');
        $ksn = '62994901190000000002';
        $bdk = '0123456789ABCDEFFEDCBA9876543210';
        
        $key = new KeySerialNumber($ksn);
        $derivedKey = DerivedKey::calculateDerivedKey($key, $bdk);
        
        $this->assertEquals('1A994C3E09D9ACEF3EA9BD4381EFA334', $derivedKey);
    }

}
