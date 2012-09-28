<?php

require_once __DIR__ . '/../src/Utility.php';
require_once __DIR__ . '/../src/KeySerialNumber.php';

class DerivedKey
{
    const _1FFFFF = "1FFFFF";
    const _100000 = "100000";
    const _E00000 = "E00000";

    /**
     * Calculate the derived key from the KSN and BDK
     * 
     * @param ksn
     *            Key Serial Number
     * @param bdk
     *            Base Derivation Key
     * @return Derived Key
     */
    public static function calculateDerivedKey(KeySerialNumber $ksn, $bdk)
    {
        // Copy IPEK into CURKEY
        $curKey = self::calculateIpek($ksn, $bdk);

        // R8 is Register 8
        // Copy KSNR into R8
        $unpaddedKsn = $ksn->getUnpaddedKsn();
        $r8 = substr($unpaddedKsn, -16);

        // Clear the 21 right most bits of R8
        $r8 = Utility::andHexStringOffset($r8, self::_E00000, strlen($r8) - 6);

        // R3 is Register 3
        // Copy the 21 right-most bits of KSNR into R3
        $r3 = Utility::andHexStringOffset($ksn->getTransactionCounter(), self::_1FFFFF, 0);

        $shiftr = self::_100000;


        // WARNING: Here be MAGIC. I got this code from the Thales Simulator
        // http://thalessim.codeplex.com project and I don't understand it.
        // Have a look at https://bitbucket.org/joxley/crypto-utils for a description of how I think DUKPT works. If you
        // know better, please tell me <john.oxley@gmail.com>

        while ($shiftr > 0) {
            $temp = Utility::andHexString($shiftr, $r3);
            if ($temp != 0) {
                $r8 = Utility::orHexStringOffset($r8, $shiftr, strlen($r8) - 6);
                $r8a = Utility::xorHexString($r8, substr($curKey, 16, 32));
                $r8a = Utility::desEncrypt(substr($curKey, 0, 16), $r8a);
                $r8a = Utility::xorHexString($r8a, substr($curKey, 16, 32));

                $curKey = Utility::xorHexString($curKey, "C0C0C0C000000000C0C0C0C000000000");

                $r8b = Utility::xorHexString(substr($curKey, 16, 32), $r8);
                $r8b = Utility::desEncrypt(substr($curKey, 0, 16), $r8b);
                $r8b = Utility::xorHexString($r8b, substr($curKey, 16, 32));

                $curKey = $r8b . $r8a;
            }
            $shiftr = Utility::shiftRightHexString($shiftr);
        }

        $curKey = Utility::xorHexString($curKey, "00000000000000FF00000000000000FF");

        return $curKey;
    }

    /**
     * Calculate the Initial Pin Encryption Key from the current KSN
     * 
     * @param ksn
     *            Key Serial Number
     * @param bdk
     *            Base Derivation Key
     * @return IPEK
     */
    public static function calculateIpek(KeySerialNumber $ksn, $bdk)
    {
        $iKsn = substr(Utility::andHexStringOffset($ksn->getPaddedKsn(), "E00000", 14), 0, 16);
        $ipek = self::calculateIpekFromInitialKsn($iKsn, $bdk);
        $ksn->setInitialKey($ipek);
        return $ipek;
    }

    /**
     * Calculate the Initial Pin Encryption Key from the initial KSN
     * 
     * @param iKsn
     *            Initial Key Serial Number
     * @param bdk
     *            Base Derivation Key
     * @return IPEK
     */
    public static function calculateIpekFromInitialKsn($iKsn, $bdk)
    {
        $ipek = Utility::tripleDesEncrypt($bdk, $iKsn);
        $xorBdk = Utility::xorHexString($bdk, "C0C0C0C000000000C0C0C0C000000000");
        $ipek = $ipek . Utility::tripleDesEncrypt($xorBdk, $iKsn);
        return $ipek;
    }

}
