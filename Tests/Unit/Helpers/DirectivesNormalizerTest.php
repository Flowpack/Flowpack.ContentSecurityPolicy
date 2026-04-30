<?php

declare(strict_types=1);

namespace Flowpack\ContentSecurityPolicy\Tests\Unit\Helpers;

use Flowpack\ContentSecurityPolicy\Exceptions\DirectivesNormalizerException;
use Flowpack\ContentSecurityPolicy\Helpers\DirectivesNormalizer;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(DirectivesNormalizer::class)]
#[CoversClass(DirectivesNormalizerException::class)]
class DirectivesNormalizerTest extends TestCase
{
    public function testNormalizesKeyValueDirectives(): void
    {
        $actual = DirectivesNormalizer::normalize([
            'base-uri' => [
                'test.com' => true,
            ],
            'script-src' => [
                'self' => true,
                'unsafe-inline' => true,
                'example.com' => true,
                'another-example.com' => true,
            ],
        ]);
        self::assertSame([
            'base-uri' => ['test.com'],
            'script-src' => ['self', 'unsafe-inline', 'example.com', 'another-example.com'],
        ], $actual);
    }

    public function testExcludesFalseValues(): void
    {
        $actual = DirectivesNormalizer::normalize([
            'base-uri' => [
                'test.com' => true,
                'another-example.com' => false,
            ],
            'script-src' => [
                'self' => true,
                'unsafe-inline' => false,
                'example.com' => true,
                'another-example.com' => false,
            ],
        ]);
        self::assertSame([
            'base-uri' => ['test.com'],
            'script-src' => ['self', 'example.com'],
        ], $actual);
    }

    public function testRemovesDirectiveWithEmptyStringKey(): void
    {
        $actual = DirectivesNormalizer::normalize([
            'base-uri' => ['' => true],
            'script-src' => ['self' => true],
        ]);
        self::assertSame(['script-src' => ['self']], $actual);
    }

    public function testRemovesEmptyDirectiveArray(): void
    {
        $actual = DirectivesNormalizer::normalize([
            'base-uri' => [],
            'script-src' => [],
        ]);
        self::assertSame([], $actual);
    }

    public function testRemovesNullDirective(): void
    {
        $actual = DirectivesNormalizer::normalize([
            'base-uri' => null,
            'script-src' => ['self' => true],
        ]);
        self::assertSame(['script-src' => ['self']], $actual);
    }

    public function testSkipsTopLevelIntKeyedDirective(): void
    {
        // @phpstan-ignore argument.type
        $actual = DirectivesNormalizer::normalize([
            'base-uri',
            'script-src' => [],
        ]);
        self::assertSame([], $actual);
    }

    public function testDeprecatedListFormatThrowsException(): void
    {
        $this->expectException(DirectivesNormalizerException::class);
        DirectivesNormalizer::normalize([
            'script-src' => ['self', 'unsafe-inline'],
        ]);
    }

    public function testMixedIntAndStringKeysThrowException(): void
    {
        $this->expectException(DirectivesNormalizerException::class);
        $this->expectExceptionMessageMatches("/must be defined as an object with string keys and boolean values/");
        DirectivesNormalizer::normalize([
            'script-src' => [
                'self' => true,
                'example.com',
                'another-example.com' => true,
            ],
        ]);
    }

    public function testNonBooleanValueThrowsException(): void
    {
        $this->expectException(DirectivesNormalizerException::class);
        $this->expectExceptionMessageMatches("/the values must be boolean/");
        DirectivesNormalizer::normalize([
            'script-src' => [
                'self' => true,
                'unsafe-inline' => 'foo bar',
            ],
        ]);
    }
}
