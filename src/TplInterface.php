<?php

declare(strict_types=1);

/*
 * eduVPN - End-user friendly VPN.
 *
 * Copyright: 2016-2021, The Commons Conservancy eduVPN Programme
 * SPDX-License-Identifier: AGPL-3.0+
 */

namespace LC\Portal;

interface TplInterface
{
    /**
     * @param array<string,mixed> $templateVariables
     */
    public function addDefault(array $templateVariables): void;

    /**
     * @param array<string,mixed> $templateVariables
     */
    public function render(string $templateName, array $templateVariables = []): string;
}