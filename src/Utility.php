<?php

class Utility
{
    public static function hex2bin($h)
    {
        if (!is_string($h)) return null;
        $r = '';
        for ($a = 0; $a < strlen($h); $a += 2) {
            $r .= chr(hexdec($h{$a} . $h{($a+1)}));
        }

        return $r;
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
    public static function andHexStringOffset($input, $mask, $offset) {
        $moddedInput = $input;

        if (strlen($input) % 2 == 1) {
            $moddedInput = "0" . $input;
        }

        $data = self::hex2bin($moddedInput);

        $moddedMask = $mask;

        if (strlen($mask) % 2 == 1) {
            $moddedMask = $mask . "F";
        }

        $maskData = self::hex2bin($moddedMask);

        $os = $offset / 2;
        $endPoint = $os + strlen($maskData);

        for ($i = $os; $i < strlen($data) && $i < $endPoint; $i++) {
            $a = $data[$i];
            $b = $maskData[$i - $os];
            $data[$i] = ($a & $b);
        }

        // The substring is to strip off the padded "0"
        $len = strlen($input);

        $encodedData = strtoupper(bin2hex($data));

        return substr($encodedData, strlen($encodedData) - $len);
    }

    /**
     * DES Encrypt the data under the key
     *
     * @param key
     *            Key
     * @param data
     *            Data
     * @return Encrypted data
     */
    public static function desEncrypt($key, $data) {
        $ivSize = mcrypt_get_iv_size(MCRYPT_DES, MCRYPT_MODE_CBC);
        $iv = mcrypt_create_iv($ivSize, MCRYPT_RAND);
        $encryptedData = mcrypt_encrypt(MCRYPT_DES, self::hex2bin($key), self::hex2bin($data), MCRYPT_MODE_CBC, $iv);
        return strtoupper(bin2hex($encryptedData));
    }

    /**
     * Convert two hex strings to byte[] and OR them from the offset
     *
     * @param input
     *            First string
     * @param mask
     *            Second string
     * @param offset
     *            Offset
     * @return ORed result
     */
    public static function orHexStringOffset($input, $mask, $offset)
    {
        if (strlen($mask) % 2 == 1) {
            $mask = "0" . $mask;
        }

        $data = self::hex2bin($input);
        $maskData = self::hex2bin($mask);
        $os = $offset / 2;
        $endPoint = $os + strlen($maskData);

        for ($i = $os; $i < strlen($data) && $i < $endPoint; $i++) {
            $a = $data[$i];
            $b = $maskData[$i - $os];
            $data[$i] = ($a | $b);
        }

        return strtoupper(bin2hex($data));
    }

    /**
     * Pad a string to the left
     *
     * @param data
     *            String to pad
     * @param length
     *            Length of resulting string
     * @param padChar
     *            pad character
     * @return Padded string
     */
    public static function padLeft($data, $length, $padChar)
    {
        return str_pad($data, $length, $padChar, STR_PAD_LEFT);
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
        $result = self::padLeft(decbin($r), strlen(decbin(hexdec($str))), '0');
        return dechex(bindec($result));
    }

    /**
     * 3DES Encrypt the data
     *
     * @param key
     *            Key to encrypt with
     * @param data
     *            Data to be encrypted
     * @return Hex string of encrypted data
     */
    public static function tripleDesEncrypt($key, $data)
    {
        $ivSize = mcrypt_get_iv_size(MCRYPT_3DES, MCRYPT_MODE_ECB);
        $iv = mcrypt_create_iv($ivSize);
        $encryptedData = mcrypt_encrypt(MCRYPT_3DES, self::hex2bin($key), self::hex2bin($data), MCRYPT_MODE_ECB, $iv);
        return strtoupper(bin2hex($encryptedData));
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
    public static function xorHexString($input, $mask) {
        $data = self::hex2bin($input);
        $maskData = self::hex2bin($mask);

        $result = $data ^ $maskData;
        return strtoupper(bin2hex($result));
    }
}
