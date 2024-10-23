<?php

declare(strict_types=1);

namespace Unit\Model;

use Flowpack\ContentSecurityPolicy\Model\Directive;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(Directive::class)]
class DirectiveTest extends TestCase
{
    public function testIsValidDirectiveShouldReturnTrue(): void
    {
        self::assertTrue(Directive::isValidDirective('media-src'));
    }

    public function testIsValidDirectiveShouldReturnFalse(): void
    {
        self::assertFalse(Directive::isValidDirective('bar'));
    }
}
