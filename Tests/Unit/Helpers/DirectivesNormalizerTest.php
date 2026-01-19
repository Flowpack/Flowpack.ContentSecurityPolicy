<?php

declare(strict_types=1);

namespace Unit\Helpers;

use Flowpack\ContentSecurityPolicy\Exceptions\DirectivesNormalizerException;
use Flowpack\ContentSecurityPolicy\Helpers\DirectivesNormalizer;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;

#[CoversClass(DirectivesNormalizer::class)]
#[CoversClass(DirectivesNormalizerException::class)]
class DirectivesNormalizerTest extends TestCase
{
    private readonly LoggerInterface&MockObject $loggerMock;

    protected function setUp(): void
    {
        parent::setUp();
        $this->loggerMock = $this->createMock(LoggerInterface::class);
    }

    public function testDeprecatedConfiguration(): void
    {
        // deprecated list configuration should still work but log deprecation warnings
        $this->loggerMock->expects($this->atLeast(4))->method('warning');

        $actual = DirectivesNormalizer::normalize([
            'base-uri' => [
                'test.com',
            ],
            'script-src' => [
                'self',
                'unsafe-inline',
                'example.com',
                'another-example.com',
            ],
        ], $this->loggerMock);
        $expected = [
            'base-uri' => [
                'test.com',
            ],
            'script-src' => [
                'self',
                'unsafe-inline',
                'example.com',
                'another-example.com',
            ],
        ];
        self::assertSame($expected, $actual);

        // empty directives should be removed
        $actual = DirectivesNormalizer::normalize([
            'base-uri' => [],
            'script-src' => [
                'self',
                'unsafe-inline',
                'example.com',
                'another-example.com',
            ],
        ], $this->loggerMock);
        $expected = [
            'script-src' => [
                'self',
                'unsafe-inline',
                'example.com',
                'another-example.com',
            ],
        ];
        self::assertSame($expected, $actual);

        // empty directive entries should be removed
        // empty directives should be removed
        $actual = DirectivesNormalizer::normalize([
            'base-uri' => [
                '',
            ],
            'script-src' => [
                'self',
                'unsafe-inline',
                'example.com',
                'another-example.com',
            ],
        ], $this->loggerMock);
        $expected = [
            'script-src' => [
                'self',
                'unsafe-inline',
                'example.com',
                'another-example.com',
            ],
        ];
        self::assertSame($expected, $actual);

        // empty directives should be removed
        $actual = DirectivesNormalizer::normalize([
            'base-uri' => [],
            'script-src' => [],
        ], $this->loggerMock);
        $expected = [];

        self::assertSame($expected, $actual);
    }

    public function testConfiguration(): void
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
        ], $this->loggerMock);
        $expected = [
            'base-uri' => [
                'test.com',
            ],
            'script-src' => [
                'self',
                'unsafe-inline',
                'example.com',
                'another-example.com',
            ],
        ];
        self::assertSame($expected, $actual);

        // empty directive entries should be removed
        // empty directives should be removed
        $actual = DirectivesNormalizer::normalize([
            'base-uri' => [
                '' => true,
            ],
            'script-src' => [
                'self' => true,
                'unsafe-inline' => true,
                'example.com' => true,
                'another-example.com' => true,
            ],
        ], $this->loggerMock);
        $expected = [
            'script-src' => [
                'self',
                'unsafe-inline',
                'example.com',
                'another-example.com',
            ],
        ];
        self::assertSame($expected, $actual);

        $actual = DirectivesNormalizer::normalize([
            'base-uri' => [],
            'script-src' => [],
        ], $this->loggerMock);
        $expected = [
        ];
        self::assertSame($expected, $actual);

        $actual = DirectivesNormalizer::normalize([
            'base-uri' => null,
            'script-src' => [],
        ], $this->loggerMock);

        self::assertSame($expected, $actual);

        // @phpstan-ignore argument.type
        $actual = DirectivesNormalizer::normalize([
            'base-uri',
            'script-src' => [],
        ], $this->loggerMock);

        self::assertSame($expected, $actual);
    }

    public function testConfigurationWithDirectivesUsingFalse(): void
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
        ], $this->loggerMock);
        $expected = [
            'base-uri' => [
                'test.com',
            ],
            'script-src' => [
                'self',
                'example.com',
            ],
        ];
        self::assertSame($expected, $actual);
    }

    public function testInvalidDirectiveExceptionForMixedConfig(): void
    {
        $this->expectException(DirectivesNormalizerException::class);
        $this->expectExceptionMessageMatches("/must be defined as a list OR an object/");
        DirectivesNormalizer::normalize([
            'script-src' => [
                'self' => true,
                'unsafe-inline' => true,
                'example.com',
                'another-example.com' => true,
            ],
        ], $this->loggerMock);
    }

    public function testInvalidDirectiveExceptionForWrongKeyValue(): void
    {
        $this->expectException(DirectivesNormalizerException::class);
        $this->expectExceptionMessageMatches("/the values must be boolean/");
        DirectivesNormalizer::normalize([
            'script-src' => [
                'self' => true,
                'unsafe-inline' => 'foo bar',
                'example.com' => true,
                'another-example.com' => true,
            ],
        ], $this->loggerMock);
    }
}
