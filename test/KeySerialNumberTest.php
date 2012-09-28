<?php

require_once __DIR__ . '/../src/KeySerialNumber.php';

class KeySerialNumberTest
{
    public function testStripKsnGood()
    {
        $ksn      = "FFFF123456789";
        $expected = "123456789";
		$actual   = KeySerialNumber::stripKsn($ksn);
		$this->assertEquals($expected, $actual);
	}


    public function testStripKsnNoPadding()
    {
        $ksn    = "FFF1234567890";
		$actual = KeySerialNumber::stripKsn($ksn);
		$this->assertEquals($ksn, $actual);
	}


    public function testConstructor()
    {
        $ksnDescriptor = "834";
        $ksn           = "0123456789321987";
        $key           = new KeySerialNumber($ksn, $ksnDescriptor);
        $this->assertEquals("01234567", $key->getBaseKeyId());
        $this->assertEquals("8932", $key->getTrsmId());
        $this->assertEquals("01987", $key->getTransactionCounter());
    }


    public function testKsnConstructingPlanned()
    {
        $termId  = "87654321";
        $stan    = "246802";
        $ksnStr  = $termId + "654" + $stan;
        $ksnDesc = "803";
        $ksn     = new KeySerialNumber($ksnStr, $ksnDesc);

        $this->assertEquals($termId, $ksn->getBaseKeyId());
        $this->assertEquals("654", $ksn->getTrsmId());
        $this->assertEquals("0" + $stan, $ksn->getTransactionCounter());
    }


    public function testPack()
    {
        $ksnDescriptor = "834";
        $ksnStr        = "0123456789321987";
        $ksn           = new KeySerialNumber($ksnStr, $ksnDescriptor);
        $actual        = $ksn->pack();
        $expected      = Utility::hex2bin($ksn->getPaddedKsn());

        $this->assertEquals($expected, $actual);
    }
}
