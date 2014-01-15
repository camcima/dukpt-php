# camcima/dukpt-php #

[![Scrutinizer Continuous Inspections](https://scrutinizer-ci.com/g/camcima/dukpt-php/badges/general.png?s=f09827625e225aba7fee07e459c206b915110bf6)](https://scrutinizer-ci.com/g/camcima/dukpt-php/)
[![Scrutinizer Quality Score](https://scrutinizer-ci.com/g/camcima/dukpt-php/badges/quality-score.png?s=f07fa733dff54e72f15e451bb1fda98a0fc2a27a)](https://scrutinizer-ci.com/g/camcima/dukpt-php/)
[![Code Coverage](https://scrutinizer-ci.com/g/camcima/dukpt-php/badges/coverage.png?s=fcf8931173798e3a38a7a787deb8b9364a9ef36c)](https://scrutinizer-ci.com/g/camcima/dukpt-php/)

A library to handle [DUKPT](http://en.wikipedia.org/wiki/Derived_unique_key_per_transaction "DUKPT") decryption.

## DUKPT Reference ##

DUKPT is defined in [ANSI X9.24-1:2009](http://webstore.ansi.org/RecordDetail.aspx?sku=ANSI+X9.24-1%3A2009 "ANSI X9.24-1:2009") standard.

## Glossary ##

- **3DES** - Triple DES (see DES);
- **AES** - Advanced Encryption Standard;
- **BDK** - Base Derivation Key;
- **DES** - Data Encryption Standard;
- **DUKPT** - Derived Unique Key Per Transaction;
- **KSN** - Key Serial Number;
- **IPEK** - Initial Pin Encryption Key;
- **MAC** - Message Authentication Code

## Brief Explanation ##

DUKPT is a standard that deals with encryption key management for credit card readers. It was invented by Visa in the 80's.

Using DUPKT, the card reader encrypts each transaction with a unique key. This key is derived from a base derivation key (BDK) using a complicated algorithm implemented in this library.

The derived key is calculated from the BDK and the KSN, a serial number formed by the device identifier (unique) and a serial number starting at 1. This serial counter has 21 bits. This would allow more the 2 million uses, but the standard states that only binary numbers that have less than or equal to 10 "one" bits can be used, because the algorithm is very CPU intensive and each "one" bit requires additional calculations.

Based on the BDK and the KSN, the algorithm calculates the IPEK, which is the base for calculating the future keys.

Note that for each BDK/KSN pair, different keys are generated for different uses:

- PIN Encryption Key
- MAC Request Key
- MAC Response Key
- Data Request Key
- Data Response Key

The device I had used the `Data Request Key` to encrypt the credit card data.


## Installation ##

- Include the library in your `composer.json`;

```
"require": {
...
"camcima/dukpt-php": "dev-master"
}
```

- Run `composer update`;

## Usage ##

To calculate the decryption key you must have the KSN and BDK.

```php
<?php

use DUKPT\DerivedKey;
use DUKPT\KeySerialNumber;
use DUKPT\Utility;

$ksnObj = new KeySerialNumber($ksn);
$decryptionKey = DerivedKey::calculateDataEncryptionRequestKey($ksnObj, $bdk);
```

And to decrypt using 3DES:


```php
<?php

use DUKPT\DerivedKey;
use DUKPT\KeySerialNumber;
use DUKPT\Utility;

$decryptedData = Utility::hex2bin(
                    Utility::removePadding(
                        Utility::tripleDesDecrypt($encryptedHexData, $decryptionKey, true)
                    )
                  );
```

The last parameter of the `tripleDesDecrypt` method changes the encryption mode to CBC3 (true), while the normal mode is ECB. I did this because we tested a chinese device that used this DES mode.

If you want to see working examples, checkout the [tests](https://github.com/camcima/dukpt-php/tree/master/src/DUKPT/Test "tests").

## Notes ##

Be aware that there are some DES/3DES/AES implementation differences between devices, as DES has many modes (ECB, CBC, CFB, OFB, ...). If it doesn't work, try another mode...


