<?php

/*
 * eduVPN - End-user friendly VPN.
 *
 * Copyright: 2016-2019, The Commons Conservancy eduVPN Programme
 * SPDX-License-Identifier: AGPL-3.0+
 */

namespace LetsConnect\Portal\Tests;

use LetsConnect\Portal\HttpClient\HttpClientInterface;
use LetsConnect\Portal\HttpClient\Response;
use RuntimeException;

class TestForeignKeyHttpClient implements HttpClientInterface
{
    /**
     * @param string                $requestUri
     * @param array<string, string> $requestHeaders
     *
     * @return Response
     */
    public function get($requestUri, array $requestHeaders = [])
    {
        switch ($requestUri) {
            case 'https://static.eduvpn.nl/disco/secure_internet_dev.json':
                return new Response(
                    200,
                    file_get_contents(sprintf('%s/data/secure_internet_dev.json', __DIR__)),
                    ['Content-Type' => 'application/json']
                );
            case 'https://static.eduvpn.nl/disco/secure_internet_dev.json.sig':
                return new Response(
                    200,
                    file_get_contents(sprintf('%s/data/secure_internet_dev.json.sig', __DIR__)),
                    ['Content-Type' => 'application/pgp-signature']
                );
            case 'https://static.eduvpn.nl/disco/secure_internet_dev.wrong.json':
                return new Response(
                    200,
                    file_get_contents(sprintf('%s/data/secure_internet_dev.wrong.json', __DIR__)),
                    ['Content-Type' => 'application/json']
                );
            case 'https://static.eduvpn.nl/disco/secure_internet_dev.wrong.json.sig':
                return new Response(
                    200,
                    file_get_contents(sprintf('%s/data/secure_internet_dev.wrong.json.sig', __DIR__)),
                    ['Content-Type' => 'application/pgp-signature']
                );
            default:
                throw new RuntimeException('no such requestUri');
        }
    }
}