<?php

require_once __DIR__ . '/../src/KeySerialNumber.php';
require_once __DIR__ . '/../src/DerivedKey.php';

class KeySerialNumberTest extends PHPUnit_Framework_TestCase
{
    public function testStripKsnGood()
    {
        $ksn = "FFFF123456789";
        $expected = "123456789";
        $actual = KeySerialNumber::stripKsn($ksn);
        $this->assertEquals($expected, $actual);
    }

    public function testStripKsnNoPadding()
    {
        $ksn = "FFF1234567890";
        $actual = KeySerialNumber::stripKsn($ksn);
        $this->assertEquals($ksn, $actual);
    }

    public function testConstructor()
    {
        $ksn = "0123456789321987";
        $key = new KeySerialNumber($ksn);
        $this->assertEquals("FFFF012345678920", $key->getBaseKeyId());
    }

    public function testDeriveInitialKey()
    {
        $bdk = '0123456789ABCDEFFEDCBA9876543210';
        $ksn = 'FFFF9876543210E00000';

        $ksnObj = new KeySerialNumber($ksn);
        $ksnObj->calculateIpek($bdk);

        $this->assertEquals('6AC292FAA1315B4D858AB3A3D7D5933A', $ksnObj->getInitialKey());
    }

    public function testDeriveFirstKey()
    {
        $bdk = '0123456789ABCDEFFEDCBA9876543210';
        $ksn = 'FFFF9876543210E00001';

        $ksnObj = new KeySerialNumber($ksn);
        $key = DerivedKey::calculateDerivedKey($ksnObj, $bdk);

        $this->assertEquals('448D3F076D8304036A55A3D7E0055A78', $key);
    }

}
