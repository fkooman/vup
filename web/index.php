<?php

declare(strict_types=1);

/*
 * eduVPN - End-user friendly VPN.
 *
 * Copyright: 2016-2021, The Commons Conservancy eduVPN Programme
 * SPDX-License-Identifier: AGPL-3.0+
 */

require_once dirname(__DIR__).'/vendor/autoload.php';
$baseDir = dirname(__DIR__);

use fkooman\OAuth\Server\PdoStorage as OAuthStorage;
use fkooman\OAuth\Server\Signer\EdDSA;
use fkooman\SeCookie\Cookie;
use fkooman\SeCookie\CookieOptions;
use fkooman\SeCookie\Session;
use fkooman\SeCookie\SessionOptions;
use LC\Portal\Config;
use LC\Portal\ConnectionManager;
use LC\Portal\Dt;
use LC\Portal\Expiry;
use LC\Portal\FileIO;
use LC\Portal\Http\AccessHook;
use LC\Portal\Http\AdminHook;
use LC\Portal\Http\AdminPortalModule;
use LC\Portal\Http\Auth\ClientCertAuthModule;
use LC\Portal\Http\Auth\DbCredentialValidator;
use LC\Portal\Http\Auth\LdapCredentialValidator;
use LC\Portal\Http\Auth\MellonAuthModule;
use LC\Portal\Http\Auth\PhpSamlSpAuthModule;
use LC\Portal\Http\Auth\RadiusCredentialValidator;
use LC\Portal\Http\Auth\ShibAuthModule;
use LC\Portal\Http\Auth\UserPassAuthModule;
use LC\Portal\Http\CsrfProtectionHook;
use LC\Portal\Http\DisabledUserHook;
use LC\Portal\Http\HtmlResponse;
use LC\Portal\Http\LogoutModule;
use LC\Portal\Http\OAuthModule;
use LC\Portal\Http\PasswdModule;
use LC\Portal\Http\Request;
use LC\Portal\Http\SeCookie;
use LC\Portal\Http\Service;
use LC\Portal\Http\SeSession;
use LC\Portal\Http\UpdateUserInfoHook;
use LC\Portal\Http\UserPassModule;
use LC\Portal\Http\VpnPortalModule;
use LC\Portal\HttpClient\CurlHttpClient;
use LC\Portal\LdapClient;
use LC\Portal\OAuth\ClientDb;
use LC\Portal\OAuth\VpnOAuthServer;
use LC\Portal\OpenVpn\CA\VpnCa;
use LC\Portal\OpenVpn\TlsCrypt;
use LC\Portal\ServerInfo;
use LC\Portal\Storage;
use LC\Portal\SysLogger;
use LC\Portal\Tpl;
use LC\Portal\VpnDaemon;
use LC\Portal\WireGuard\ServerConfig as WireGuardServerConfig;

$logger = new SysLogger('vpn-user-portal');

try {
    $request = Request::createFromGlobals();
    FileIO::createDir($baseDir.'/data', 0700);
    $config = Config::fromFile($baseDir.'/config/config.php');

    $templateDirs = [
        $baseDir.'/views',
        $baseDir.'/config/views',
    ];
    $translationDirs = [
        $baseDir.'/locale',
        $baseDir.'/config/locale',
    ];
    if (null !== $styleName = $config->styleName()) {
        $templateDirs[] = $baseDir.'/views/'.$styleName;
        $templateDirs[] = $baseDir.'/config/views/'.$styleName;
        $translationDirs[] = $baseDir.'/locale/'.$styleName;
        $translationDirs[] = $baseDir.'/config/locale/'.$styleName;
    }

    $ca = new VpnCa($baseDir.'/data/ca');

    $sessionExpiry = Expiry::calculate(
        $config->sessionExpiry(),
        $ca->caCert()->validTo()
    );

    $dateTime = Dt::get();
    if ($dateTime->add(new DateInterval('PT30M')) >= $dateTime->add($sessionExpiry)) {
        throw new RuntimeException('sessionExpiry MUST be > PT30M');
    }

    $db = new PDO(
        $config->dbConfig($baseDir)->dbDsn(),
        $config->dbConfig($baseDir)->dbUser(),
        $config->dbConfig($baseDir)->dbPass()
    );
    $storage = new Storage($db, $baseDir.'/schema');
    $storage->update();

    $cookieOptions = CookieOptions::init()->withPath($request->getRoot())->withSameSiteLax();
    if (!$config->secureCookie()) {
        $cookieOptions = $cookieOptions->withoutSecure();
    }
    $cookieBackend = new SeCookie(new Cookie($cookieOptions->withMaxAge(60 * 60 * 24 * 90)));
    $sessionOptions = SessionOptions::init();
    $sessionBackend = new SeSession(new Session($sessionOptions, $cookieOptions->withSameSiteStrict()));

    // determine whether or not we want to use another language for the UI
    if (null === $uiLanguage = $request->getCookie('L')) {
        $uiLanguage = $config->defaultLanguage();
    }
    $tpl = new Tpl($templateDirs, $translationDirs, $baseDir.'/web', $uiLanguage);

    // Authentication
    $authModuleCfg = $config->authModule();

    $templateDefaults = [
        'enableConfigDownload' => $config->enableConfigDownload(),
        'requestUri' => $request->getUri(),
        'requestRoot' => $request->getRoot(),
        'requestRootUri' => $request->getRootUri(),
        'enabledLanguages' => $config->requireStringArray('enabledLanguages', ['en-US']),
        'portalVersion' => trim(FileIO::readFile($baseDir.'/VERSION')),
        'isAdmin' => false,
        'uiLanguage' => $uiLanguage,
        '_show_logout_button' => true,
    ];

    $tpl->addDefault($templateDefaults);

    $service = new Service();
    $service->addBeforeHook(new CsrfProtectionHook());

    switch ($authModuleCfg) {
        case 'BasicAuthModule':
            $authModule = new LC\Portal\Http\Auth\BasicAuthModule(
                [
                    'foo' => 'bar',
                ]
            );

            break;

        case 'PhpSamlSpAuthModule':
            $authModule = new PhpSamlSpAuthModule($config->s('PhpSamlSpAuthModule'));

            break;

        case 'DbAuthModule':
            $authModule = new UserPassAuthModule($sessionBackend, $tpl);
            $service->addModule(
                new UserPassModule(
                    new DbCredentialValidator($storage),
                    $sessionBackend,
                    $tpl
                )
            );
            // when using local database, users are allowed to change their own
            // password
            $service->addModule(
                new PasswdModule(
                    new DbCredentialValidator($storage),
                    $tpl,
                    $storage
                )
            );

            break;

        case 'MellonAuthModule':
            $authModule = new MellonAuthModule($config->mellonAuthConfig());

            break;

        case 'ShibAuthModule':
            $authModule = new ShibAuthModule(
                $config->s('ShibAuthModule')->requireString('userIdAttribute'),
                $config->s('ShibAuthModule')->requireStringArray('permissionAttributeList', [])
            );

            break;

        case 'ClientCertAuthModule':
            $authModule = new ClientCertAuthModule();

            break;

        case 'RadiusAuthModule':
            $authModule = new UserPassAuthModule($sessionBackend, $tpl);
            $service->addModule(
                new UserPassModule(
                    new RadiusCredentialValidator(
                        $logger,
                        $config->s('RadiusAuthModule')->requireStringArray('serverList'),
                        $config->s('RadiusAuthModule')->optionalString('addRealm'),
                        $config->s('RadiusAuthModule')->optionalString('nasIdentifier'),
                        $config->s('RadiusAuthModule')->optionalInt('permissionAttribute'),
                    ),
                    $sessionBackend,
                    $tpl
                )
            );

            break;

        case 'LdapAuthModule':
            // XXX move ldapClient to LdapCredentialValidator
            $ldapClient = new LdapClient(
                $config->ldapAuthConfig()->ldapUri()
            );
            $authModule = new UserPassAuthModule($sessionBackend, $tpl);
            $service->addModule(
                new UserPassModule(
                    new LdapCredentialValidator(
                        $config->ldapAuthConfig(),
                        $logger,
                        $ldapClient
                    ),
                    $sessionBackend,
                    $tpl
                )
            );

            break;

        default:
            throw new RuntimeException('unsupported authentication mechanism');
    }

    $service->setAuthModule($authModule);
    $tpl->addDefault(['authModule' => $authModuleCfg]);

    if (null !== $accessPermissionList = $config->optionalStringArray('accessPermissionList')) {
        // hasAccess
        $service->addBeforeHook(new AccessHook($accessPermissionList));
    }

    $service->addBeforeHook(new DisabledUserHook($storage));
    $service->addBeforeHook(new UpdateUserInfoHook($sessionBackend, $storage, $authModule));

    // isAdmin
    $adminHook = new AdminHook(
        $config->requireStringArray('adminPermissionList', []),
        $config->requireStringArray('adminUserIdList', []),
        $tpl
    );

    $service->addBeforeHook($adminHook);
    $oauthClientDb = new ClientDb();
    $oauthStorage = new OAuthStorage($db, 'oauth_');
    $wireGuardServerConfig = new WireGuardServerConfig(FileIO::readFile($baseDir.'/config/wireguard.secret.key'), $config->wgPort());
    $oauthSigner = new EdDSA(FileIO::readFile($baseDir.'/config/oauth.key'));
    $tlsCrypt = new TlsCrypt($baseDir.'/data');
    $serverInfo = new ServerInfo(
        $ca,
        $tlsCrypt,
        FileIO::readFile($baseDir.'/config/wireguard.public.key'),
        $config->wgPort(),
        $oauthSigner->publicKey()
    );

    $connectionManager = new ConnectionManager($config, new VpnDaemon(new CurlHttpClient(), $logger), $storage);

    // portal module
    $vpnPortalModule = new VpnPortalModule(
        $config,
        $tpl,
        $cookieBackend,
        $sessionBackend,
        $connectionManager,
        $storage,
        $oauthStorage,
        $serverInfo,
        $oauthClientDb,
        $sessionExpiry
    );
    $service->addModule($vpnPortalModule);

    $adminPortalModule = new AdminPortalModule(
        $baseDir.'/data',
        $config,
        $tpl,
        $connectionManager,
        $storage,
        $oauthStorage,
        $adminHook,
        $serverInfo
    );
    $service->addModule($adminPortalModule);

    // OAuth module
    $oauthServer = new VpnOAuthServer(
        $oauthStorage,
        $oauthClientDb,
        $oauthSigner
    );
    $oauthServer->setAccessTokenExpiry($config->apiConfig()->tokenExpiry());
    $oauthServer->setRefreshTokenExpiry($sessionExpiry);

    $oauthModule = new OAuthModule(
        $tpl,
        $oauthServer
    );
    $service->addModule($oauthModule);
    $service->addModule(new LogoutModule($authModule, $sessionBackend));

    $service->run($request)->send();
} catch (Exception $e) {
    $logger->error($e->getMessage());
    // XXX getTraceAsString is most likely not secure to just return as HTML!
//    $response = new HtmlResponse($e->getMessage().$e->getTraceAsString(), [], 500);
    // XXX we MUST escape whatever we return as HTML!
    $response = new HtmlResponse(htmlentities($e->getMessage()), [], 500);
    $response->send();
}
