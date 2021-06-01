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

use LC\Portal\Config;
use LC\Portal\OpenVpn\DaemonSocket;
use LC\Portal\OpenVpn\DaemonWrapper;
use LC\Portal\Storage;
use LC\Portal\SysLogger;

try {
    $dateTime = new DateTimeImmutable();

    $config = Config::fromFile($baseDir.'/config/config.php');
    $storage = new Storage(
        new PDO(
            $config->s('Db')->requireString('dbDsn', 'sqlite://'.$baseDir.'/data/db.sqlite'),
            $config->s('Db')->optionalString('dbUser'),
            $config->s('Db')->optionalString('dbPass')
        ),
        $baseDir.'/schema'
    );

    // XXX make sure all SysLogger use argv[0]
    $logger = new SysLogger('vpn-user-portal');

    $daemonWrapper = new DaemonWrapper(
        $config,
        $storage,
        new DaemonSocket($baseDir.'/config/vpn-daemon', $config->vpnDaemonTls()),
        $logger
    );

    foreach ($daemonWrapper->getConnectionList(null) as $profileId => $connectionInfoList) {
        foreach ($connectionInfoList as $connectionInfo) {
            // check expiry of certificate
            $expiresAt = new DateTimeImmutable($connectionInfo['valid_to']);
            if ($dateTime > $expiresAt) {
                // certificate expired, disconnect!
                $daemonWrapper->killClient($connectionInfo['common_name']);
            }
        }
    }
} catch (Exception $e) {
    echo sprintf('ERROR: %s', $e->getMessage()).\PHP_EOL;
    exit(1);
}