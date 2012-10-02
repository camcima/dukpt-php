<?php

require_once __DIR__ . '/../src/DerivedKey.php';
require_once __DIR__ . '/../src/KeySerialNumber.php';

class CreateIpekTest extends PHPUnit_Framework_TestCase
{

    public function testCalculateIpekForReal() {
        $bdk = '0123456789ABCDEF';
        $ksn = '0123456789A00001';
        $ksnObj = new KeySerialNumber($ksn);
        $ksnObj->calculateIpek($bdk);
        $actual = $ksnObj->getInitialKey();
        $expected = '78DF942D65A2ECE6';
        
        $this->assertEquals($expected, $actual);
    }
    
}