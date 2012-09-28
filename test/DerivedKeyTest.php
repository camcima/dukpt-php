<?php

require_once __DIR__ . '/../src/DerivedKey.php';
require_once __DIR__ . '/../src/KeySerialNumber.php';

class DerivedKeyTest extends PHPUnit_Framework_TestCase
{
    public function testCalculateIpek()
    {
        $ksnDescriptor = "834";
        $ksn = "0123456789321987";
        $key = new KeySerialNumber($ksn, $ksnDescriptor);
        $actual = DerivedKey::calculateIpek($key, "0123456789ABCDEFFEDCBA9876543210");
        $expected = "19890EA798095287FEAEA2A780DA3F0E";

        $this->assertEquals($expected, $actual);
    }

    public function testCalculateDerivedKey()
    {
        $ksnDescriptor = "834";
        $ksn = "0123456789321987";
        $key = new KeySerialNumber($ksn, $ksnDescriptor);
        $bdk = "0123456789ABCDEFFEDCBA9876543210";
        $actual = DerivedKey::calculateDerivedKey($key, $bdk);
        $expected = "DC3170007A69CD6EDDF55E6B21E73855";

        $this->assertEquals($expected, $actual);
    }

}
