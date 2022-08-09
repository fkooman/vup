<?php

declare(strict_types=1);

/*
 * eduVPN - End-user friendly VPN.
 *
 * Copyright: 2016-2022, The Commons Conservancy eduVPN Programme
 * SPDX-License-Identifier: AGPL-3.0+
 */

namespace Vpn\Portal\OpenVpn;

use Vpn\Portal\Cfg\KeyConfig;
use Vpn\Portal\FileIO;
use Vpn\Portal\Validator;

class TlsCrypt
{
    private string $keyDir;
    private KeyConfig $keyConfig;

    public function __construct(string $keyDir, KeyConfig $keyConfig)
    {
        $this->keyDir = $keyDir;
        $this->keyConfig = $keyConfig;
    }

    public function get(string $profileId): string
    {
        // validate profileId also here, to make absolutely sure...
        Validator::profileId($profileId);

        if ($this->keyConfig->hasTlsCryptKey($profileId)) {
            return $this->keyConfig->tlsCryptKey($profileId);
        }

        // do we (still) have one on disk we need to migrate?
        $tlsCryptKeyFile = $this->keyDir.'/tls-crypt-'.$profileId.'.key';
        if (FileIO::exists($tlsCryptKeyFile)) {
            // import it into the database and delete the file from disk
            $tlsCryptKey = FileIO::read($tlsCryptKeyFile);
            $this->keyConfig->setTlsCryptKey($profileId, $tlsCryptKey);
            FileIO::delete($tlsCryptKeyFile);

            return $tlsCryptKey;
        }

        $tlsCryptKey = self::generate();
        $this->keyConfig->setTlsCryptKey($profileId, $tlsCryptKey);

        return $tlsCryptKey;
    }

    private static function generate(): string
    {
        // Same as $(openvpn --genkey --secret <file>)
        $randomData = wordwrap(sodium_bin2hex(random_bytes(256)), 32, "\n", true);

        return <<< EOF
            #
            # 2048 bit OpenVPN static key
            #
            -----BEGIN OpenVPN Static key V1-----
            {$randomData}
            -----END OpenVPN Static key V1-----
            EOF;
    }
}
