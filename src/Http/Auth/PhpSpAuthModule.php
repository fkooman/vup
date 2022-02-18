<?php

declare(strict_types=1);

/*
 * eduVPN - End-user friendly VPN.
 *
 * Copyright: 2016-2022, The Commons Conservancy eduVPN Programme
 * SPDX-License-Identifier: AGPL-3.0+
 */

namespace Vpn\Portal\Http\Auth;

use fkooman\SAML\SP\Api\AuthOptions;
use fkooman\SAML\SP\Api\SpAuth;
use Vpn\Portal\Cfg\PhpSpAuthConfig;
use Vpn\Portal\Http\Exception\HttpException;
use Vpn\Portal\Http\RedirectResponse;
use Vpn\Portal\Http\Request;
use Vpn\Portal\Http\Response;
use Vpn\Portal\Http\UserInfo;

class PhpSpAuthModule extends AbstractAuthModule
{
    private PhpSpAuthConfig $config;
    private SpAuth $spAuth;

    public function __construct(PhpSpAuthConfig $config)
    {
        $this->config = $config;
        $this->spAuth = new SpAuth();
    }

    public function userInfo(Request $request): ?UserInfo
    {
        $authOptions = $this->getAuthOptions();
        if (!$this->spAuth->isAuthenticated($authOptions)) {
            return null;
        }

        $activeSession = $this->spAuth->activeSession($authOptions);
        // XXX verify AuthnContextClassRef?!
        $attributeList = $activeSession->attributeList();
        $userIdAttribute = $this->config->userIdAttribute();
        if (!\array_key_exists($userIdAttribute, $attributeList)) {
            throw new HttpException(sprintf('missing user_id attribute "%s"', $userIdAttribute), 500);
        }

        return new UserInfo(
            $attributeList[$userIdAttribute][0],
            $this->getPermissionList($attributeList)
        );
    }

    public function startAuth(Request $request): ?Response
    {
        return new RedirectResponse($this->spAuth->getLoginURL($this->getAuthOptions()));
    }

    public function triggerLogout(Request $request): Response
    {
        return new RedirectResponse(
            $request->getScheme().'://'.$request->getAuthority().'/php-saml-sp/logout?'.http_build_query(['ReturnTo' => $request->requireReferrer()])
        );
    }

    private function getAuthOptions(): AuthOptions
    {
        $authOptions = new AuthOptions();
        if (null !== $authnContext = $this->config->authnContext()) {
            $authOptions->withAuthnContextClassRef($authnContext);
        }

        return $authOptions;
    }

    /**
     * @param array<string,array<string>> $attributeList
     *
     * @return array<string>
     */
    private function getPermissionList(array $attributeList): array
    {
        $permissionList = [];
        foreach ($this->config->permissionAttributeList() as $permissionAttribute) {
            if (\array_key_exists($permissionAttribute, $attributeList)) {
                $permissionList = array_merge($permissionList, $attributeList[$permissionAttribute]);
            }
        }

        return $permissionList;
    }
}
