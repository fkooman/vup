<?php

declare(strict_types=1);

/*
 * eduVPN - End-user friendly VPN.
 *
 * Copyright: 2016-2022, The Commons Conservancy eduVPN Programme
 * SPDX-License-Identifier: AGPL-3.0+
 */

namespace Vpn\Portal\Cfg;

use Vpn\Portal\Cfg\Exception\ConfigException;
use Vpn\Portal\Storage;

/**
 * Keys are stored in the database now, so we depend on the database to get
 * configuration values out.
 */
class KeyConfig
{
    private Storage $storage;

    public function __construct(Storage $storage)
    {
        $this->storage = $storage;
    }

    public function tlsCryptKey(string $profileId): string
    {
        return $this->requireString('tls-crypt-'.$profileId.'.key');
    }

    public function hasTlsCryptKey(string $profileId): bool
    {
        return null !== $this->optionalString('tls-crypt-'.$profileId.'.key');
    }

    public function setTlsCryptKey(string $profileId, string $tlsCryptKey): void
    {
        $this->storage->setCfg('tls-crypt-'.$profileId.'.key', $tlsCryptKey);
    }

    public function hasWgKey(int $nodeNumber): bool
    {
        return null !== $this->optionalString('wireguard.'.$nodeNumber.'.public.key');
    }

    public function wgKey(int $nodeNumber): string
    {
        return $this->requireString('wireguard.'.$nodeNumber.'.public.key');
    }

    public function setWgKey(int $nodeNumber, string $wgKey): void
    {
        $this->storage->setCfg('wireguard.'.$nodeNumber.'.public.key', $wgKey);
    }

    private function requireString(string $k, ?string $d = null): string
    {
        if (null === $v = $this->optionalString($k)) {
            if (null !== $d) {
                return $d;
            }

            throw new ConfigException('key "'.$k.'" not available');
        }

        return $v;
    }

    private function optionalString(string $k): ?string
    {
        $cfgData = $this->storage->getCfg();
        if (!\array_key_exists($k, $cfgData)) {
            return null;
        }

        return $cfgData[$k];
    }
}
