<?php

require_once __DIR__ . '/../src/DerivedKey.php';
require_once __DIR__ . '/../src/KeySerialNumber.php';

class CreateIpekTest extends PHPUnit_Framework_TestCase
{
    public function createIpek()
    {
        $iKsn = "FFFF406716000000";
        $bdk = "0123456789ABCDEFFEDCBA9876543210";
        $ipek = DerivedKey::calculateIpekFromInitialKsn($iKsn, $bdk);
        $this->assertEquals("B58237EC094C75169E405D7F5A3C2CC0", $ipek);
    }

}