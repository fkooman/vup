<?php

declare(strict_types=1);

/*
 * eduVPN - End-user friendly VPN.
 *
 * Copyright: 2016-2022, The Commons Conservancy eduVPN Programme
 * SPDX-License-Identifier: AGPL-3.0+
 */

namespace Vpn\Portal\WireGuard;

use Vpn\Portal\Cfg\KeyConfig;
use Vpn\Portal\Exception\ServerConfigException;
use Vpn\Portal\FileIO;

class ServerConfig
{
    private string $keyDir;
    private KeyConfig $keyConfig;
    private int $wgPort;

    public function __construct(string $keyDir, KeyConfig $keyConfig, int $wgPort)
    {
        $this->keyDir = $keyDir;
        $this->keyConfig = $keyConfig;
        $this->wgPort = $wgPort;
    }

    /**
     * @param array<\Vpn\Portal\Cfg\ProfileConfig> $profileConfigList
     */
    public function get(array $profileConfigList, int $nodeNumber, string $publicKey): ?string
    {
        $ipFourList = [];
        $ipSixList = [];
        foreach ($profileConfigList as $profileConfig) {
            if (!$profileConfig->wSupport()) {
                // we only want WireGuard profiles
                continue;
            }
            $ipFourList[] = $profileConfig->wRangeFour($nodeNumber)->firstHostPrefix();
            $ipSixList[] = $profileConfig->wRangeSix($nodeNumber)->firstHostPrefix();
        }
        $ipList = implode(',', array_merge($ipFourList, $ipSixList));

        if (0 === \count($ipFourList) || 0 === \count($ipSixList)) {
            // apparently we did not have any WireGuard profiles...
            return null;
        }

        $this->registerPublicKey($nodeNumber, $publicKey);

        return <<< EOF
            [Interface]
            Address = {$ipList}
            ListenPort = {$this->wgPort}
            PrivateKey = {{PRIVATE_KEY}}
            EOF;
    }

    private static function comparePublicKey(string $publicKey, string $existingPublicKey, int $nodeNumber): void
    {
        if ($publicKey !== $existingPublicKey) {
            throw new ServerConfigException(sprintf('node "%d" already registered a public key, but it does not match anymore, delete the existing public key first', $nodeNumber));
        }
    }

    /**
     * We register the node's WireGuard public key, iff we do not have one yet
     * for that particular node. If we do, and it doesn't match what we have
     * we scream.
     */
    private function registerPublicKey(int $nodeNumber, string $publicKey): void
    {
        if ($this->keyConfig->hasWgKey($nodeNumber)) {
            self::comparePublicKey($publicKey, $this->keyConfig->wgKey($nodeNumber), $nodeNumber);

            return;
        }

        // do we (still) have one on disk we need to migrate?
        $publicKeyFile = sprintf('%s/wireguard.%d.public.key', $this->keyDir, $nodeNumber);
        if (FileIO::exists($publicKeyFile)) {
            $existingPublicKey = FileIO::read($publicKeyFile);
            self::comparePublicKey($publicKey, $existingPublicKey, $nodeNumber);
            // migrate to database
            $this->keyConfig->setWgKey($nodeNumber, $publicKey);
            FileIO::delete($publicKeyFile);

            return;
        }

        // we do not yet have it register, register it now
        $this->keyConfig->setWgKey($nodeNumber, $publicKey);
    }
}
