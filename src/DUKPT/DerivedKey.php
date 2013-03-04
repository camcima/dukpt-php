<?php

namespace DUKPT;

class DerivedKey
{
    /**
     * Constant used in the Shift Register
     */
    const _100000 = "100000";

    /**
     * Variant constant to generate the PIN Encryption Key
     */
    const VARIANT_CONSTANT_PIN_ENCRYPTION = "00000000000000FF00000000000000FF";

    /**
     * Variant constant to generate the MAC Request/Both Ways Encryption Key
     */
    const VARIANT_CONSTANT_MAC_REQUEST = "000000000000FF00000000000000FF00";

    /**
     * Variant constant to generate the MAC Response Encryption Key
     */
    const VARIANT_CONSTANT_MAC_RESPONSE = "00000000FF00000000000000FF000000";

    /**
     * Variant constant to generate the Data Request/Both Ways Encryption Key
     */
    const VARIANT_CONSTANT_DATA_REQUEST = "0000000000FF00000000000000FF0000";

    /**
     * Variant constant to generate the Data Response Encryption Key
     */
    const VARIANT_CONSTANT_DATA_RESPONSE = "000000FF00000000000000FF00000000";

    /**
     * Calculate Derived Key for the given KSN
     * 
     * @param KeySerialNumber $ksn
     *      Key Serial Number
     * @param string $bdk
     *      Hexadecimal representation of the Base Derivation Key
     * 
     * @return string
     *      Derived Key in hexadecimal representation
     */
    public static function calculateDerivedKey(KeySerialNumber $ksn, $bdk)
    {
        $ksn->calculateIpek($bdk);
        $curKey = $ksn->getInitialKey();

        $ksnr = $ksn->getKsnr();
        $r8 = Utility::binstr2hex(substr(Utility::hex2binstr($ksnr), 0, 43) . str_repeat('0', 21));

        $r3 = $ksn->getTransactionCounter();

        $shiftr = self::_100000;

        while ($shiftr > 0) {
            $temp = Utility::andHexString($shiftr, $r3);

            if ($temp != 0) {
                $r8 = Utility::orHexString($r8, $shiftr, 43);
                $r8a = Utility::xorHexString($r8, self::rightHalf($curKey));
                $r8a = Utility::desEncrypt($r8a, self::leftHalf($curKey));
                $r8a = Utility::xorHexString($r8a, self::rightHalf($curKey));

                $curKey = Utility::xorHexString($curKey, "C0C0C0C000000000C0C0C0C000000000");

                $r8b = Utility::xorHexString(self::rightHalf($curKey), $r8);
                $r8b = Utility::desEncrypt($r8b, self::leftHalf($curKey));
                $r8b = Utility::xorHexString(self::rightHalf($curKey), $r8b);

                $curKey = $r8b . $r8a;
            }

            $shiftr = Utility::shiftRightHexString($shiftr);
        }

        return $curKey;
    }
    
    /**
     * Calculate Derived Key for the given KSN
     * 
     * Chinese Version of the Algorithm
     * 
     * @param KeySerialNumber $ksn
     *      Key Serial Number
     * @param string $bdk
     *      Hexadecimal representation of the Base Derivation Key
     * 
     * @return string
     *      Derived Key in hexadecimal representation
     */
    public static function getNowKey(KeySerialNumber $ksn, $bdk) {
        $hexNowKey = $bdk;
        $tmpCount = hexdec($ksn->getTransactionCounter());
        $j = 0;
        
        for ($i = 0; $i < 21; $i++) {
            if ($tmpCount & 0x01) {
                $j++;
            }
            $tmpCount = $tmpCount >> 1;
        }
        
        $tmpCount = hexdec($ksn->getTransactionCounter());
        $k =0;
        $x = 0x100000;
        while ($j--) {
            for ($i = 0; $i < 21; $i++) {
                if ($tmpCount & 0x100000) {
                    break;
                }
                $tmpCount <<= 1;
                $x >>= 1;
            }
            $k += $x;
            $tmpCount <<= 1;
            $x >>= 1;
            $ksn = self::combineKsn($ksn, $k);
            $hexNowKey = self::generateKey($hexNowKey, $ksn);
        }
        
        return $hexNowKey;
    }

    /**
     * Transform KSN
     * 
     * Chinese code
     * 
     * @param \DUKPT\KeySerialNumber $ksn
     * @param int $transactionCounter
     * 
     * @return \DUKPT\KeySerialNumber
     */
    protected static function combineKsn(KeySerialNumber $ksn, $transactionCounter)
    {
        $hexKsn = $ksn->getPaddedKsn();
        $hexKsn7 = Utility::getByteOnHexString($hexKsn, 7);
        $hexKsn7 = Utility::andHexString($hexKsn7, 'E0');
        $hexKsn = Utility::setByteOnHexString($hexKsn, $hexKsn7, 7);
        $hexKsn = Utility::setByteOnHexString($hexKsn, '00', 8);
        $hexKsn = Utility::setByteOnHexString($hexKsn, '00', 9);
        
        $hexTemp = Utility::andHexString(dechex($transactionCounter >> 16), '1F');
        $hexKsn7 = Utility::getByteOnHexString($hexKsn, 7);
        $hexKsn7 = dechex(hexdec($hexKsn7) + hexdec($hexTemp));
        $hexKsn = Utility::setByteOnHexString($hexKsn, $hexKsn7, 7);

        $hexTemp = Utility::andHexString(dechex($transactionCounter >> 8), 'FF');
        $hexKsn8 = Utility::getByteOnHexString($hexKsn, 8);
        $hexKsn8 = dechex(hexdec($hexKsn8) + hexdec($hexTemp));
        $hexKsn = Utility::setByteOnHexString($hexKsn, $hexKsn8, 8);

        $hexTemp = Utility::andHexString(dechex($transactionCounter), 'FF');
        $hexKsn9 = Utility::getByteOnHexString($hexKsn, 9);
        $hexKsn9 = dechex(hexdec($hexKsn9) + hexdec($hexTemp));
        $hexKsn = Utility::setByteOnHexString($hexKsn, $hexKsn9, 9);

        return new KeySerialNumber($hexKsn);
    }
    
    /**
     * Generate Key
     * 
     * Chinese Code
     * 
     * @param string $hexNowKey
     * @param \DUKPT\KeySerialNumber $ksn
     * 
     * @return string
     */
    protected static function generateKey($hexNowKey, KeySerialNumber $ksn) {
        $hexCr1 = substr($ksn->getUnpaddedKsn(), 0, 16);
        $hexCr2 = Utility::xorHexString($hexCr1, substr($hexNowKey, 16, 16));
        $hexCr2 = Utility::desEncrypt(substr($hexCr2,0, 16), substr($hexNowKey, 0, 16));
        $hexCr2 = Utility::xorHexString($hexCr2, substr($hexNowKey, 16, 16));
        $hexNowKey = Utility::xorHexString(KeySerialNumber::_C0C0, substr($hexNowKey, 0, 32));
        $hexCr1 = Utility::xorHexString($hexCr1, substr($hexNowKey, 16, 16));
        $hexCr1 = Utility::desEncrypt(substr($hexCr1,0, 16), substr($hexNowKey, 0, 16));
        $hexCr1 = Utility::xorHexString($hexCr1, substr($hexNowKey, 16, 16));
        $hexNowKey = $hexCr1 . $hexCr2;
        
        return $hexNowKey;
    }
    
    /**
     * Calculate the Variant Key
     * 
     * @param string $derivedKey
     *      Derived Key in hexadecimal representation
     * @param string $variantConstant
     *      Variant Constant in hexadecimal representation
     * 
     * @return string
     *      Variant key in hexadecimal representation
     */
    public static function calculateVariantKey($derivedKey, $variantConstant)
    {
        $result = Utility::xorHexString($derivedKey, $variantConstant);
        return $result;
    }

    /**
     * Calculate the PIN Encryption Key
     * 
     * @param KeySerialNumber $ksn
     *      Key Serial Number
     * @param string $bdk
     *      Hexadecimal representation of the Base Derivation Key
     * 
     * @return string
     *      PIN Encryption Key in hexadecimal representation
     */
    public static function calculatePinEncryptionKey(KeySerialNumber $ksn, $bdk)
    {
        $derivedKey = self::calculateDerivedKey($ksn, $bdk);
        $variantKey = self::calculateVariantKey($derivedKey, self::VARIANT_CONSTANT_PIN_ENCRYPTION);

        return $variantKey;
    }

    /**
     * Calculate the MAC Request/Both Ways Encryption Key
     * 
     * @param KeySerialNumber $ksn
     *      Key Serial Number
     * @param string $bdk
     *      Hexadecimal representation of the Base Derivation Key
     * 
     * @return string
     *      MAC Request/Both Ways Encryption Key in hexadecimal representation
     */
    public static function calculateMacRequestKey(KeySerialNumber $ksn, $bdk)
    {
        $derivedKey = self::calculateDerivedKey($ksn, $bdk);
        $variantKey = self::calculateVariantKey($derivedKey, self::VARIANT_CONSTANT_MAC_REQUEST);

        return $variantKey;
    }

    /**
     * Calculate the MAC Response Ways Encryption Key
     * 
     * @param KeySerialNumber $ksn
     *      Key Serial Number
     * @param string $bdk
     *      Hexadecimal representation of the Base Derivation Key
     * 
     * @return string
     *      MAC Response Encryption Key in hexadecimal representation
     */
    public static function calculateMacResponseKey(KeySerialNumber $ksn, $bdk)
    {
        $derivedKey = self::calculateDerivedKey($ksn, $bdk);
        $variantKey = self::calculateVariantKey($derivedKey, self::VARIANT_CONSTANT_MAC_RESPONSE);

        return $variantKey;
    }

    /**
     * Calculate the Data Request/Both Ways Encryption Key
     * 
     * @param KeySerialNumber $ksn
     *      Key Serial Number
     * @param string $bdk
     *      Hexadecimal representation of the Base Derivation Key
     * 
     * @return string
     *      Data Request/Both Ways Encryption Key in hexadecimal representation
     */
    public static function calculateDataEncryptionRequestKey(KeySerialNumber $ksn, $bdk)
    {
        $derivedKey = self::calculateDerivedKey($ksn, $bdk);
        $variantKey = self::calculateVariantKey($derivedKey, self::VARIANT_CONSTANT_DATA_REQUEST);

        $variantKeyLeft = self::leftHalf($variantKey);
        $variantKeyRight = self::rightHalf($variantKey);

        $encryptionKeyLeft = Utility::tripleDesEncrypt($variantKeyLeft, $variantKey);
        $encryptionKeyRight = Utility::tripleDesEncrypt($variantKeyRight, $variantKey);

        $result = $encryptionKeyLeft . $encryptionKeyRight;

        return $result;
    }

    /**
     * Calculate the Data Response Ways Encryption Key
     * 
     * @param KeySerialNumber $ksn
     *      Key Serial Number
     * @param string $bdk
     *      Hexadecimal representation of the Base Derivation Key
     * 
     * @return string
     *      Data Response Encryption Key in hexadecimal representation
     */
    public static function calculateDataEncryptionResponseKey(KeySerialNumber $ksn, $bdk)
    {
        $derivedKey = self::calculateDerivedKey($ksn, $bdk);
        $variantKey = self::calculateVariantKey($derivedKey, self::VARIANT_CONSTANT_DATA_RESPONSE);

        $variantKeyLeft = self::leftHalf($variantKey);
        $variantKeyRight = self::rightHalf($variantKey);

        $encryptionKeyLeft = Utility::tripleDesEncrypt($variantKeyLeft, $variantKey);
        $encryptionKeyRight = Utility::tripleDesEncrypt($variantKeyRight, $variantKey);

        $result = $encryptionKeyLeft . $encryptionKeyRight;

        return $result;
    }

    /**
     * Get the left half of the 16-byte key
     * 
     * @param string $key
     *      16-byte key
     * 
     * @return string
     *      8-byte key
     */
    private static function leftHalf($key)
    {
        return substr($key, 0, 16);
    }

    /**
     * Get the left half of the 16-byte key
     * 
     * @param string $key
     *      16-byte key
     * 
     * @return string
     *      8-byte key
     */
    private static function rightHalf($key)
    {
        return substr($key, 16);
    }

}
