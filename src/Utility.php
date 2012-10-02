<?php

include_once('Crypt/TripleDES.php');

class Utility
{
    public static function hex2bin($h)
    {
        if (!is_string($h)) return null;
        $r = '';
        for ($a = 0; $a < strlen($h); $a += 2) {
            $r .= chr(hexdec($h{$a} . $h{($a + 1)}));
        }

        return $r;
    }

    public static function hex2binstr($hexInput)
    {
        if (strlen($hexInput) % 2 == 1) {
            $hexInput = '0' . $hexInput;
        }

        $binstr = '';
        for ($i = 0; $i < strlen($hexInput); $i = $i + 2) {
            $hex = substr($hexInput, $i, 2);

            $binstr .= str_pad(decbin(hexdec($hex)), 8, '0', STR_PAD_LEFT);
        }

        return $binstr;
    }

    public static function binstr2hex($binstrInput)
    {

        $paddedBinstrInput = str_pad($binstrInput, ceil(strlen($binstrInput) / 8) * 8, '0', STR_PAD_LEFT);

        $hex = '';
        for ($i = strlen($paddedBinstrInput); $i > 0; $i = $i - 8) {
            $binstr = substr($paddedBinstrInput, $i - 8, 8);
            $hex = str_pad(dechex(bindec($binstr)), 2, '0', STR_PAD_LEFT) . $hex;
        }

        return strtoupper($hex);
    }

    /**
     * Convert two hex strings to byte[] and AND them
     *
     * @param input
     *            First string
     * @param mask
     *            Second string
     * @return ANDed result
     */
    public static function andHexString($input, $mask)
    {
        return self::andHexStringOffset($input, $mask, 0);
    }

    /**
     * Convert two hex strings to byte[] and AND them from the offset
     *
     * @param input
     *            First string
     * @param mask
     *            Second string
     * @param offset
     *            Offset to AND from
     * @return ANDed result
     */
    public static function andHexStringOffset($input, $mask, $offset)
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
     * Convert two hex strings to byte[] and OR them from the binary offset
     *
     * @param input
     *            First string
     * @param mask
     *            Second string
     * @param offset
     *            Binary Offset
     * @return ORed result
     */
    public static function orHexStringOffset($input, $mask, $offset = 0)
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
     * Convert two hex strings to byte[] and XOR them
     *
     * @param input
     *            First string
     * @param mask
     *            Second string
     * @return XORed result
     */
    public static function xorHexString($input, $mask)
    {
        $binStr1 = self::hex2binstr($input);
        $binStr2 = self::hex2binstr($mask);

        $binXor = '';
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
     * Perform a shift right operation on a hex string
     *
     * @param str
     *            Input string
     * @return Shifted string
     */
    public static function shiftRightHexString($str)
    {
        $r = hexdec($str) >> 1;
        $result = str_pad(decbin($r), strlen(decbin(hexdec($str))), '0', STR_PAD_LEFT);
        return dechex(bindec($result));
    }

    public static function desEncrypt($data, $key)
    {
        $encryptedData = mcrypt_encrypt(MCRYPT_DES, self::hex2bin($key), self::hex2bin($data), MCRYPT_MODE_ECB);
        return strtoupper(bin2hex($encryptedData));
    }

    public static function tripleDesEncrypt($hexData, $hexKey)
    {
        //fix Crypt Library padding
        $hexKey = $hexKey . substr($hexKey, 0, 16);

        $crypt3DES = new Crypt_TripleDES(CRYPT_DES_MODE_CBC3);
        $crypt3DES->setKey(Utility::hex2bin($hexKey));
        $crypt3DES->disablePadding();

        return strtoupper(bin2hex($crypt3DES->encrypt(Utility::hex2bin($hexData))));
    }

    public static function tripleDesDecrypt($hexData, $hexKey)
    {
        //fix Crypt Library padding
        $hexKey = $hexKey . substr($hexKey, 0, 16);

        $crypt3DES = new Crypt_TripleDES(CRYPT_DES_MODE_CBC3);
        $crypt3DES->setKey(Utility::hex2bin($hexKey));
        $crypt3DES->disablePadding();

        return strtoupper(bin2hex($crypt3DES->decrypt(Utility::hex2bin($hexData))));
    }

}
