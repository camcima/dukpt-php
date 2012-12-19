<?php

namespace DUKPT\Test;

use DUKPT\Utility;

class UtilityTest extends AbstractTest
{
    public function testAndHexStringOffset()
    {
        $actual   = Utility::andHexString("012345F789ABCDEF", "E00000", 40);
        $expected = "012345F789A00000";
        $this->assertEquals($expected, $actual);
    }

    public function testAndHexStringOff()
    {
        $input    = "01987";
        $mask     = "1FFFFF";
        $actual   = Utility::andHexString($input, $mask);
        $expected = "01987";
        $this->assertEquals($expected, $actual);
    }

    public function testAndHexStringReg3()
    {
        $input    = "010000";
        $mask     = "019870";
        $actual   = Utility::andHexString($input, $mask);
        $expected = "010000";
        $this->assertEquals($expected, $actual);
    }


    public function testAndHexStringShiftTemp()
    {
        $input    = "000008";
        $mask     = "01988";
        $actual   = Utility::andHexString($input, $mask);
        $expected = "000008";
        $this->assertEquals($expected, $actual);
    }


    public function testDesEncrypt()
    {
        $key      = "0123456789ABCDEF";
        $data     = "0000000000000000";
        $expected = "D5D44FF720683D0D";
        $actual   = Utility::desEncrypt($data, $key);
        $this->assertEquals($expected, $actual);
    }


    public function testOrHexStringOffset()
    {
        $input    = "C0C0C0C0C0C0C0C0";
        $mask     = "C0C0C";
        $expected = "C0C0C0C0C0CCCCCC";
        $actual   = Utility::orHexString($input, $mask, 10);
        $this->assertEquals($expected, $actual);
    }


    public function testShiftRightHexString()
    {
        $input    = "100000";
        $expected = "080000";
        $actual   = Utility::shiftRightHexString($input);
        $this->assertEquals($expected, $actual);
    }


    public function testXorHexString()
    {
        $input    = "0123456789ABCDEF";
        $mask     = "C0C0C0C000000000C0C0C0C000000000";
        $expected = "C1E385A789ABCDEF";
        $actual   = Utility::xorHexString($input, $mask);
        $this->assertEquals($expected, $actual);
    }
    
    public function testTripleDesEncryptDecrypt() {
        $key = '0123456789ABCDEFFEDCBA9876543210';
        $data = '0123456789ABCDEF';
        
        $expected = $data;
        $actual = Utility::tripleDesDecrypt(Utility::tripleDesEncrypt($data, $key), $key, true);
        
        $this->assertEquals($expected, $actual);
    }
}
