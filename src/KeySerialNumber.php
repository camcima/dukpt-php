<?php

require_once __DIR__ . '/../src/Utility.php';

class KeySerialNumber
{
    const _C0C0 = 'c0c0c0c000000000c0c0c0c000000000';

    private $issuerIdentifierNumber;
    private $customerId;
    private $groupId;
    private $trsmId;
    private $transactionCounter;
    private $baseKeyId;
    private $paddedKsn;
    private $unpaddedKsn;
    private $initialKey;
    private $ksnr;

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

    public function stripKsn($ksn)
    {
        if (strpos($ksn, 'FFFF') === 0) {
            return substr($ksn, 4);
        }

        return $ksn;
    }

    public function getBaseKeyId()
    {
        return $this->baseKeyId;
    }

    public function getInitialKey()
    {
        return $this->initialKey;
    }

    public function getPaddedKsn()
    {
        return $this->paddedKsn;
    }

    public function getTransactionCounter()
    {
        return $this->transactionCounter;
    }

    public function getTrsmId()
    {
        return $this->trsmId;
    }

    public function getUnpaddedKsn()
    {
        return $this->unpaddedKsn;
    }

    public function getKsnr()
    {
        return $this->ksnr;
    }

    public function setInitialKey($initialKey)
    {
        $this->initialKey = $initialKey;
    }

    public function pack()
    {
        return Utility::hex2bin($this->paddedKsn);
    }

    public function calculateIpek($bdk)
    {
        $leftInitialKey = bin2hex(Utility::encrypt_3des_ede($this->baseKeyId, $bdk));
        $rightInitialKey = bin2hex(Utility::encrypt_3des_ede($this->baseKeyId, Utility::xorHexString($bdk, self::_C0C0)));

        $this->initialKey = strtoupper($leftInitialKey . $rightInitialKey);
    }

}
