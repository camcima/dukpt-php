<?php

require_once __DIR__ . '/../src/Utility.php';
require_once __DIR__ . '/../src/KeySerialNumber.php';

class DerivedKey
{
    const _100000 = "100000";
    const VARIANT_CONSTANT_PIN_ENCRYPTION = "00000000000000FF00000000000000FF";
    const VARIANT_CONSTANT_MAC_REQUEST    = "000000000000FF00000000000000FF00";
    const VARIANT_CONSTANT_MAC_RESPONSE   = "00000000FF00000000000000FF000000";
    const VARIANT_CONSTANT_DATA_REQUEST   = "0000000000FF00000000000000FF0000";
    const VARIANT_CONSTANT_DATA_RESPONSE  = "000000FF00000000000000FF00000000";

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
                $r8 = Utility::orHexStringOffset($r8, $shiftr, 59);
                $r8a = Utility::xorHexString($r8, self::rightHalf($curKey));
                $r8a = Utility::desEncrypt(self::leftHalf($curKey), $r8a);
                $r8a = Utility::xorHexString($r8a, self::rightHalf($curKey));

                $curKey = Utility::xorHexString($curKey, "C0C0C0C000000000C0C0C0C000000000");

                $r8b = Utility::xorHexString(self::rightHalf($curKey), $r8);
                $r8b = Utility::desEncrypt(self::leftHalf($curKey), $r8b);
                $r8b = Utility::xorHexString(self::rightHalf($curKey), $r8b);

                $curKey = $r8b . $r8a;
            }

            $shiftr = Utility::shiftRightHexString($shiftr);
        }

        return $curKey;
    }

    public static function calculateVariantKey($derivedKey, $variantConstant)
    {
        $result = Utility::xorHexString($derivedKey, $variantConstant);
        return $result;
    }

    public static function calculatePinEncryptionKey(KeySerialNumber $ksn, $bdk)
    {
        $derivedKey = self::calculateDerivedKey($ksn, $bdk);
        $variantKey = self::calculateVariantKey($derivedKey, self::VARIANT_CONSTANT_PIN_ENCRYPTION);

        return $variantKey;
    }

    public static function calculateMacRequestKey(KeySerialNumber $ksn, $bdk)
    {
        $derivedKey = self::calculateDerivedKey($ksn, $bdk);
        $variantKey = self::calculateVariantKey($derivedKey, self::VARIANT_CONSTANT_MAC_REQUEST);

        return $variantKey;
    }

    public static function calculateMacResponseKey(KeySerialNumber $ksn, $bdk)
    {
        $derivedKey = self::calculateDerivedKey($ksn, $bdk);
        $variantKey = self::calculateVariantKey($derivedKey, self::VARIANT_CONSTANT_MAC_RESPONSE);

        return $variantKey;
    }

    public static function calculateDataEncryptionRequestKey(KeySerialNumber $ksn, $bdk)
    {
        $derivedKey = self::calculateDerivedKey($ksn, $bdk);
        $variantKey = self::calculateVariantKey($derivedKey, self::VARIANT_CONSTANT_DATA_REQUEST);

        $variantKeyLeft = self::leftHalf($variantKey);
        $variantKeyRight = self::rightHalf($variantKey);

        $encryptionKeyLeft = Utility::encrypt_3des_ede($variantKeyLeft, $variantKey);
        $encryptionKeyRight = Utility::encrypt_3des_ede($variantKeyRight, $variantKey);

        $result = strtoupper(bin2hex($encryptionKeyLeft . $encryptionKeyRight));

        return $result;
    }

    public static function calculateDataEncryptionResponseKey(KeySerialNumber $ksn, $bdk)
    {
        $derivedKey = self::calculateDerivedKey($ksn, $bdk);
        $variantKey = self::calculateVariantKey($derivedKey, self::VARIANT_CONSTANT_DATA_RESPONSE);

        $variantKeyLeft = self::leftHalf($variantKey);
        $variantKeyRight = self::rightHalf($variantKey);

        $encryptionKeyLeft = Utility::encrypt_3des_ede($variantKeyLeft, $variantKey);
        $encryptionKeyRight = Utility::encrypt_3des_ede($variantKeyRight, $variantKey);

        $result = strtoupper(bin2hex($encryptionKeyLeft . $encryptionKeyRight));

        return $result;
    }

    private static function leftHalf($key)
    {
        return substr($key, 0, 16);
    }

    private static function rightHalf($key)
    {
        return substr($key, 16);
    }

}
