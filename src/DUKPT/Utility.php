<?php

namespace DUKPT;

use Crypt;
use phpseclib\Crypt\TripleDES;

class Utility
{
    /**
     * Convert hexadecimal string to binary
     * 
     * This function is available in PHP > 5.4
     * 
     * @param string $hexString
     * 
     * @return binary
     */
    public static function hex2bin($hexString)
    {
        if (!is_string($hexString)) return null;
        $r = '';
        for ($a = 0; $a < strlen($hexString); $a += 2) {
            $r .= chr(hexdec($hexString{$a} . $hexString{($a + 1)}));
        }

        return $r;
    }

    /**
     * Convert hexadecimal string to its binary string representation
     * 
     * @param string $hexString
     * 
     * @return string
     */
    public static function hex2binstr($hexString)
    {
        if (strlen($hexString) % 2 == 1) {
            $hexString = '0' . $hexString;
        }

        $binstr = '';
        for ($i = 0; $i < strlen($hexString); $i = $i + 2) {
            $hex = substr($hexString, $i, 2);

            $binstr .= str_pad(decbin(hexdec($hex)), 8, '0', STR_PAD_LEFT);
        }

        return $binstr;
    }

    /**
     * Convert a binary string to its hexadecimal string representation
     * 
     * @param string $binaryString
     * 
     * @return string
     */
    public static function binstr2hex($binaryString)
    {

        $paddedBinstrInput = str_pad($binaryString, ceil(strlen($binaryString) / 8) * 8, '0', STR_PAD_LEFT);

        $hex = '';
        for ($i = strlen($paddedBinstrInput); $i > 0; $i = $i - 8) {
            $binstr = substr($paddedBinstrInput, $i - 8, 8);
            $hex = str_pad(dechex(bindec($binstr)), 2, '0', STR_PAD_LEFT) . $hex;
        }

        return strtoupper($hex);
    }

    /**
     * Bitwise AND operation between hexadecimal strings with an offset
     *
     * @param string $input
     *      First hexadecimal string
     * @param string $mask
     *      Second hexadecimal string
     * @param int $offset
     *      Offset in bits
     * 
     * @return string
     *      ANDed result
     */
    public static function andHexString($input, $mask, $offset = 0)
    {
        $binStr1 = self::hex2binstr($input);
        $binStr2 = self::hex2binstr($mask);

        $binStr1 = str_pad($binStr1, max(strlen($binStr1), strlen($binStr2)), '0', STR_PAD_LEFT);
        $binStr2 = str_pad($binStr2, max(strlen($binStr1), strlen($binStr2)), '0', STR_PAD_LEFT);

        $binAnd = substr($binStr1, 0, $offset);
        for ($i = $offset; $i < strlen($binStr1); $i++) {
            if (($binStr1[$i] == 1) && ($binStr2[$i] == 1)) {
                $binAnd .= '1';
            } else {
                $binAnd .= '0';
            }
        }

        return self::binstr2hex($binAnd);
    }

    /**
     * Bitwise OR operation between hexadecimal strings with an offset
     *
     * @param string $input
     *      First hexadecimal string
     * @param string $mask
     *      Second hexadecimal string
     * @param int $offset
     *      Offset in bits
     * 
     * @return string
     *      ORed result
     */
    public static function orHexString($input, $mask, $offset = 0)
    {
        $binStr1 = self::hex2binstr($input);
        $binStr2 = self::hex2binstr($mask);

        $binStr1 = str_pad($binStr1, max(strlen($binStr1), strlen($binStr2)), '0', STR_PAD_LEFT);
        $binStr2 = str_pad($binStr2, max(strlen($binStr1), strlen($binStr2)), '0', STR_PAD_LEFT);

        $binOr = substr($binStr1, 0, $offset);
        for ($i = $offset; $i < strlen($binStr1); $i++) {
            if (($binStr1[$i] == 1) || ($binStr2[$i] == 1)) {
                $binOr .= '1';
            } else {
                $binOr .= '0';
            }
        }

        return self::binstr2hex($binOr);
    }

    /**
     * Bitwise XOR operation between hexadecimal strings
     *
     * @param string $input
     *      First hexadecimal string
     * @param string $mask
     *      Second hexadecimal string
     * @param int $offset
     *      Offset in bits
     * 
     * @return string
     *      XORed result
     */
    public static function xorHexString($input, $mask, $offset = 0)
    {
        $binStr1 = self::hex2binstr($input);
        $binStr2 = self::hex2binstr($mask);

        $binXor = substr($binStr1, 0, $offset);
        for ($i = 0; $i < strlen($binStr1); $i++) {
            if ($binStr1[$i] == $binStr2[$i]) {
                $binXor .= '0';
            } else {
                $binXor .= '1';
            }
        }

        return self::binstr2hex($binXor);
    }

    /**
     * Perform a shift right operation on a hexadecimal string
     *
     * @param string $hexString
     *      Input string
     * 
     * @return string
     *      Shifted string
     */
    public static function shiftRightHexString($hexString)
    {
        $r = hexdec($hexString) >> 1;
        $result = str_pad(decbin($r), strlen(decbin(hexdec($hexString))), '0', STR_PAD_LEFT);
        return dechex(bindec($result));
    }

    /**
     * DES Encrypt in ECB mode
     * 
     * @param string $hexData
     *      Data in hexadecimal representation
     * @param string $hexKey
     *      Key in hexadecimal representation
     * 
     * @return string
     *      Encrypted data in hexadecimal representation
     */
    public static function desEncrypt($hexData, $hexKey)
    {
        $encryptedData = mcrypt_encrypt(MCRYPT_DES, self::hex2bin($hexKey), self::hex2bin($hexData), MCRYPT_MODE_ECB);
        return strtoupper(bin2hex($encryptedData));
    }

    /**
     * DES Decrypt in ECB mode
     * 
     * @param string $hexData
     *      Ecrypted data in hexadecimal representation
     * @param string $hexKey
     *      Key in hexadecimal representation
     * 
     * @return string
     *      Decrypted data in hexadecimal representation
     */
    public static function desDecrypt($hexData, $hexKey)
    {
        $decryptedData = mcrypt_decrypt(MCRYPT_DES, self::hex2bin($hexKey), self::hex2bin($hexData), MCRYPT_MODE_ECB);
        return strtoupper(bin2hex($decryptedData));
    }

    /**
     * 3-DES Encrypt in EDE-CBC3 Mode
     * 
     * @param string $hexData
     *      Data in hexadecimal representation
     * @param string $hexKey
     *      Key in hexadecimal representation
     * 
     * @return string
     *      Encrypted data in hexadecimal representation
     */
    public static function tripleDesEncrypt($hexData, $hexKey)
    {
        //fix Crypt Library padding
        $hexKey = $hexKey . substr($hexKey, 0, 16);

        $crypt3DES = new TripleDES(TripleDES::MODE_CBC3);
        $crypt3DES->setKey(Utility::hex2bin($hexKey));
        $crypt3DES->disablePadding();

        return strtoupper(bin2hex($crypt3DES->encrypt(Utility::hex2bin($hexData))));
    }

    /**
     * 3-DES Decrypt in EDE-CBC3 Mode
     * 
     * @param string $hexEncryptedData
     *      Encrypted Data in hexadecimal representation
     * @param string $hexKey
     *      Key in hexadecimal representation
     * @param bool   $useDesModeCBC3
     *      Use DES CBC3 Mode
     * 
     * @return string
     *      Decrypted data in hexadecimal representation
     */
    public static function tripleDesDecrypt($hexEncryptedData, $hexKey, $useDesModeCBC3 = false)
    {
        //fix Crypt Library padding
        $hexKey = $hexKey . substr($hexKey, 0, 16);

        if ($useDesModeCBC3) {
            $crypt3DES = new TripleDES(TripleDES::MODE_CBC3); // IDTech uses mode CRYPT_DES_MODE_CBC3
        } else {
            $crypt3DES = new TripleDES(TripleDES::MODE_ECB); // Chinese uses mode CRYPT_DES_MODE_ECB
        }
        $crypt3DES->setKey(Utility::hex2bin($hexKey));
        $crypt3DES->disablePadding();

        return strtoupper(bin2hex($crypt3DES->decrypt(Utility::hex2bin($hexEncryptedData))));
    }

    /**
     * Get a specific byte in a hex string
     * 
     * @param string $hexString
     * @param string $byteNumber
     * 
     * @return string Byte
     */
    public static function getByteOnHexString($hexString, $byteNumber)
    {
        return substr($hexString, $byteNumber * 2, 2);
    }

    /**
     * Set a specific byte in a hex string
     * 
     * @param string $hexString
     * @param string $byte
     * @param int    $byteNumber
     * 
     * @return string Hex String
     */
    public static function setByteOnHexString($hexString, $byte, $byteNumber)
    {

        $result = '';

        // if not the first byte
        if ($byteNumber > 0) {
            $result .= substr($hexString, 0, ($byteNumber * 2));
        }

        $result .= strtoupper($byte);

        // if not the last byte
        if ($byteNumber < strlen($hexString) / 2) {
            $result .= substr($hexString, ($byteNumber + 1) * 2);
        }

        return $result;
    }

    /**
     * Remove NUL padding from string
     * 
     * @param string $hexString
     * @return string
     */
    public static function removePadding($hexString)
    {
        $binString = self::hex2bin($hexString);
        $unpaddedBinString = rtrim($binString, "\0");
        return bin2hex($unpaddedBinString);
    }

}
