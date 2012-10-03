<?php

namespace DUKPT;

class KeySerialNumber
{
    /**
     * Hexadecimal constant used in the calculation of the initial key
     */

    const _C0C0 = 'C0C0C0C000000000C0C0C0C000000000';

    /**
     * Issuer Identifier Number
     * 
     * Part of KSN (3 bytes)
     * 
     * @var string 
     */
    private $issuerIdentifierNumber;

    /**
     * Customer ID
     * 
     * Part of KSN (1 bytes)
     * 
     * @var string 
     */
    private $customerId;

    /**
     * Group ID
     * 
     * Part of KSN (1 bytes)
     * 
     * @var string 
     */
    private $groupId;

    /**
     * Tamper-Resistant Security Module ID
     * 
     * Part of KSN (19 bits)
     * 
     * @var string 
     */
    private $trsmId;

    /**
     * Transaction Counter
     * 
     * Part of KSN (21 bits)
     * 
     * @var string 
     */
    private $transactionCounter;

    /**
     * Base Key ID - Left-most 8 bytes of the padded KSN
     * 
     * The transaction counter part is zeroed
     * 
     * @var string 
     */
    private $baseKeyId;

    /**
     * KSNR - Right-most 8 bytes of the padded KSN
     * 
     * @var string 
     */
    private $ksnr;

    /**
     * KSN padded to 10 bytes
     * 
     * @var string 
     */
    private $paddedKsn;

    /**
     * Unpadded KSN (8 bytes)
     * 
     * @var string 
     */
    private $unpaddedKsn;

    /**
     * Initial Key
     * 
     * Initial PIN loaded in the TRSM
     * 
     * @var string 
     */
    private $initialKey;

    /**
     * Constructor
     * 
     * @param string $ksn
     *      KSN in hexadecimal representation
     */
    public function __construct($ksn)
    {
        if (strlen($ksn) == 20) {
            $this->paddedKsn = $ksn;
            $this->unpaddedKsn = $this->stripKsn($ksn);
        } elseif (strlen($ksn) == 16) {
            $this->unpaddedKsn = $ksn;
            $this->paddedKsn = 'FFFF' . $ksn;
        }

        $this->issuerIdentifierNumber = substr($ksn, 0, 6);
        $this->customerId = substr($ksn, 6, 2);
        $this->groupId = substr($ksn, 8, 2);
        $this->ksnr = substr($this->paddedKsn, -16);

        $binStr = str_pad(Utility::hex2binstr(substr($ksn, 10)), 40, '0', STR_PAD_LEFT);

        $this->trsmId = Utility::binstr2hex(substr($binStr, 0, 19));
        $this->transactionCounter = Utility::binstr2hex(substr($binStr, 19));

        $binBaseKey = substr(Utility::hex2binstr($this->paddedKsn), 0, 59) . str_repeat('0', 21);
        $this->baseKeyId = substr(Utility::binstr2hex($binBaseKey), 0, 16);
    }

    /**
     * Getter for the Unpadded KSN
     * 
     * @return string
     *      Unpadded KSN in hexadecimal representation
     */
    public function getUnpaddedKsn()
    {
        return $this->unpaddedKsn;
    }

    /**
     * Getter for the Padded KSN
     * 
     * @return string
     *      Padded KSN in hexadecimal representation
     */
    public function getPaddedKsn()
    {
        return $this->paddedKsn;
    }

    /**
     * Getter for the TRSM ID
     * 
     * @return string
     *      TRSM ID in hexadecimal representation
     */
    public function getTrsmId()
    {
        return $this->trsmId;
    }

    /**
     * Getter for the Transacation Counter
     * 
     * @return string
     *      Transacation Counter in hexadecimal representation
     */
    public function getTransactionCounter()
    {
        return $this->transactionCounter;
    }

    /**
     * Getter for the Base Key ID
     * 
     * @return string
     *      Base Key ID in hexadecimal representation
     */
    public function getBaseKeyId()
    {
        return $this->baseKeyId;
    }

    /**
     * Getter for the KSNR
     * 
     * @return string
     *      KSNR in hexadecimal representation
     */
    public function getKsnr()
    {
        return $this->ksnr;
    }

    /**
     * Getter fot the Initial Key
     * 
     * @return string
     *      Initial Key in hexadecimal representation
     */
    public function getInitialKey()
    {
        return $this->initialKey;
    }

    /**
     * Calculates the Inital Key loaded in the device (TRSM)
     * given the Base Derivation Key
     * 
     * @param string $bdk
     *      Base Derivation Key in hexadecimal representation
     */
    public function calculateIpek($bdk)
    {
        $leftInitialKey = Utility::tripleDesEncrypt($this->baseKeyId, $bdk);
        $rightInitialKey = Utility::tripleDesEncrypt($this->baseKeyId, Utility::xorHexString($bdk, self::_C0C0));

        $this->initialKey = $leftInitialKey . $rightInitialKey;
    }

    /**
     * Strip padding from the KSN
     * 
     * @param string $ksn
     *      KSN in hexadecimal representation
     * 
     * @return string
     *      
     */
    private function stripKsn($ksn)
    {
        if (strlen($ksn) == 20 && strpos($ksn, 'FFFF') === 0) {
            return substr($ksn, 4);
        }

        return $ksn;
    }

}
