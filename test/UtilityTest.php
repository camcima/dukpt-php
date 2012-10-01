<?php

require_once __DIR__ . '/../src/Utility.php';

class UtilityTest extends PHPUnit_Framework_TestCase
{
    public function testAndHexStringOffset()
    {
        $actual   = Utility::andHexStringOffset("012345F789ABCDEF", "E00000", 6);
        $expected = "012345E00000CDEF";
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
        $mask     = "01987";
        $actual   = Utility::andHexString($input, $mask);
        $expected = "010000";
        $this->assertEquals($expected, $actual);
    }


    public function testAndHexStringShiftTemp()
    {
        $input    = "000008";
        $mask     = "01987";
        $actual   = Utility::andHexString($input, $mask);
        $expected = "000008";
        $this->assertEquals($expected, $actual);
    }


    public function testDesEncrypt()
    {
        $key      = "0123456789ABCDEF";
        $data     = "0000000000000000";
        $expected = "D5D44FF720683D0D";
        $actual   = Utility::desEncrypt($key, $data);
        $this->assertEquals($expected, $actual);
    }


    public function testOrHexStringOffset()
    {
        $input    = "C0C0C0C0C0C0C0C0";
        $mask     = "C0C0C";
        $expected = "C0C0C0C0C0CCCCCC";
        $actual   = Utility::orHexStringOffset($input, $mask, 10);
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
}
