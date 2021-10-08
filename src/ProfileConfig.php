<?php

declare(strict_types=1);

/*
 * eduVPN - End-user friendly VPN.
 *
 * Copyright: 2016-2021, The Commons Conservancy eduVPN Programme
 * SPDX-License-Identifier: AGPL-3.0+
 */

namespace LC\Portal;

use LC\Portal\Exception\ConfigException;

class ProfileConfig
{
    use ConfigTrait;

    private array $configData;

    public function __construct(array $configData)
    {
        $this->configData = $configData;
    }

    public function profileId(): string
    {
        return $this->requireString('profileId');
    }

    public function vpnProto(): string
    {
        return $this->requireString('vpnProto');
    }

    public function hostName(): string
    {
        return $this->requireString('hostName');
    }

    public function range(): IP
    {
        return IP::fromIpPrefix($this->requireString('range'));
    }

    public function range6(): IP
    {
        return IP::fromIpPrefix($this->requireString('range6'));
    }

    public function displayName(): string
    {
        return $this->requireString('displayName');
    }

    public function defaultGateway(): bool
    {
        return $this->requireBool('defaultGateway', true);
    }

    /**
     * @return array<string>
     */
    public function routes(): array
    {
        return $this->requireStringArray('routes', []);
    }

    /**
     * @return array<string>
     */
    public function dns(): array
    {
        return $this->requireStringArray('dns', []);
    }

    public function clientToClient(): bool
    {
        return $this->requireBool('clientToClient', false);
    }

    public function listenIp(): string
    {
        return $this->requireString('listenIp', '::');
    }

    public function enableLog(): bool
    {
        return $this->requireBool('enableLog', false);
    }

    public function enableAcl(): bool
    {
        return $this->requireBool('enableAcl', false);
    }

    /**
     * @return array<string>
     */
    public function aclPermissionList(): array
    {
        return $this->requireStringArray('aclPermissionList', []);
    }

    public function nodeUrl(): string
    {
        return $this->requireString('nodeUrl', 'http://127.0.0.1:41194');
    }

    /**
     * OpenVPN only.
     *
     * @return array<string>
     */
    public function vpnProtoPorts(): array
    {
        if ('wireguard' === $this->vpnProto()) {
            throw new ConfigException('"vpnProtoPorts" is only used for OpenVPN');
        }

        return $this->requireStringArray('vpnProtoPorts', ['udp/1194', 'tcp/1194']);
    }

    /**
     * OpenVPN only.
     *
     * @return array<string>
     */
    public function exposedVpnProtoPorts(): array
    {
        if ('wireguard' === $this->vpnProto()) {
            throw new ConfigException('"exposedVpnProtoPorts" is only used for OpenVPN');
        }

        return $this->requireStringArray('exposedVpnProtoPorts', []);
    }

    public function blockLan(): bool
    {
        return $this->requireBool('blockLan', false);
    }

    public function dnsDomain(): ?string
    {
        return $this->optionalString('dnsDomain');
    }

    /**
     * @return array<string>
     */
    public function dnsDomainSearch(): array
    {
        return $this->requireStringArray('dnsDomainSearch', []);
    }
}
