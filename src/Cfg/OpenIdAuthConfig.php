<?php

declare(strict_types=1);

/*
 * eduVPN - End-user friendly VPN.
 *
 * Copyright: 2016-2022, The Commons Conservancy eduVPN Programme
 * SPDX-License-Identifier: AGPL-3.0+
 */

namespace Vpn\Portal\Cfg;

class OpenIdAuthConfig
{
    use ConfigTrait;

    private array $configData;

    public function __construct(array $configData)
    {
        $this->configData = $configData;
    }

    public function userIdAttribute(): string
    {
        return $this->requireString('userIdAttribute') ?: 'REMOTE_USER';
    }

    /**
     * @return array<string>
     */
    public function permissionAttributeList(): array
    {
        return $this->requireStringArray('permissionAttributeList', []);
    }


    /**
     * @return string
     */
    public function cookieName(): string
    {
        return $this->requireString('cookieName') ?: 'mod_auth_openidc_session';
    }

    /** 
    * @return string
    */
   public function redirectURI(): string
   {
       return $this->requireString('redirectURI') ;
   }

    

}
