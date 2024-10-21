<?php

declare(strict_types=1);

namespace Flowpack\ContentSecurityPolicy\Model;

class Directive
{
    private const VALID_DIRECTIVES = [
        'child-src',
        'connect-src',
        'default-src',
        'font-src',
        'frame-src',
        'img-src',
        'manifest-src',
        'media-src',
        'object-src',
        'prefetch-src',
        'script-src',
        'style-src',
        'style-src-attr',
        'style-src-elem',
        'worker-src',
        'base-uri',
        'plugin-types',
        'sandbox',
        'form-action',
        'frame-ancestors',
        'navigate-to',
        'report-uri',
        'report-to',
        'require-sri-for',
        'upgrade-insecure-requests',
        'block-all-mixed-content',
        'trusted-types',
        'require-trusted-types-for',
    ];

    public static function isValidDirective(string $directive): bool
    {
        return in_array($directive, self::VALID_DIRECTIVES);
    }

}
