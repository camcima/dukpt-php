<?php

require_once __DIR__ . '/../src/DerivedKey.php';
require_once __DIR__ . '/../src/KeySerialNumber.php';

class DerivedKeyTest extends PHPUnit_Framework_TestCase
{

    public function testCalculateDerivedKey()
    {
        $ksn = "FFFF9876543210E00001";
        $key = new KeySerialNumber($ksn);
        $bdk = "0123456789ABCDEFFEDCBA9876543210";
        $actual = DerivedKey::calculateDerivedKey($key, $bdk);
        $expected = "DC3170007A69CD6EDDF55E6B21E73855";

        $this->assertEquals($expected, $actual);
    }

}
