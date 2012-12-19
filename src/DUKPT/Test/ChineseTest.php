<?php

namespace DUKPT\Test;

use DUKPT\Utility;
use DUKPT\KeySerialNumber;
use DUKPT\DerivedKey;


class ChineseTest extends AbstractTest
{

    public function testDesEncrypt()
    {
        $key      = "FFFFFFFFFFFFFFFF";
        $data     = "FFFF0000001FFFEF";
        $expected = "4A80AEEC27348072";
        $actual   = Utility::desEncrypt($data, $key);
        $this->assertEquals($expected, $actual);
    }

    public function testXorHexString()
    {
        $input    = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
        $mask     = "C0C0C0C000000000C0C0C0C000000000";
        $expected = "3F3F3F3FFFFFFFFF3F3F3F3FFFFFFFFF";
        $actual   = Utility::xorHexString($input, $mask);
        $this->assertEquals($expected, $actual);
    }
        
    public function testTripleDesEncryptDecrypt() {
        $key = 'B3203CEA55C3BC4CA675A00A1BF70A7A';
        $encryptedData = 'D38AD7DF6CCE394993CFB7AE0AE69041AA835E7E6B9389435D63DE6796F1031FD9A711AB99026950EAB8B57E05C384C8FE46FEF60935B5CFE6E6016C6CC7A1131DA59CBEE7644FA1EB856512C57464A5BD43FEAF3660052620CA931EE47ABB94D5153FB3CD3A4D781DA59CBEE7644FA1518A097C15346B6C';

        $expected = '2542343030323437393437303731373439335E4645524E414E44455A2F4D415243555320432020202020205E313330323230313030303030202020202020202030303133363030303030303F3B343030323437393437303731373439333D31333032323031303030303031333630303030303F0000000000';
        $actual = Utility::tripleDesDecrypt($encryptedData, $key);
        
        $this->assertEquals($expected, $actual);
    }
    
    public function testGetNowKey() {
        $bdk = 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF';
        $ksn = 'FFFFFFFFFFFFFFE00022';
        
        $expected = 'B3203CEA55C3BC4CA675A00A1BF70A7A';
        $actual = DerivedKey::getNowKey(new KeySerialNumber($ksn), $bdk);
        $this->assertEquals($expected, $actual);
    }
    
    public function testDecryptSwipe() {
        $encryptedData = 'EE83560CE7D7A276196EF815A8E5D58838336A87CE90052B35BE5C78D49BCED40BE2531A3F6FF89E7DFDCF8E73747EEB92712F56CA47CA1A04EB8C41DFDF57C24E4ECF9A1C56C121BE467045CE8DA7EFA6F3D91F65D4247FF8588BE9AE6C082E6BA4A9F03EFDF21B4E4ECF9A1C56C121A37A63AFE2FD0F2B';
        $bdk = 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF';
        $ksn = new KeySerialNumber('FFFFFFFFFFFFFFE00024');
        
        $expected = '2542343030323437393437303731373439335E4645524E414E44455A2F4D415243555320432020202020205E313330323230313030303030202020202020202030303133363030303030303F3B343030323437393437303731373439333D31333032323031303030303031333630303030303F0000000000';
        $derivedKey = DerivedKey::getNowKey($ksn, $bdk);
        $actual = Utility::tripleDesDecrypt($encryptedData, $derivedKey);
        $this->assertEquals($expected, $actual);
    }
    
}
