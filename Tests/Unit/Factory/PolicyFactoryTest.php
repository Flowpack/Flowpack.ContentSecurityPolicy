<?php

declare(strict_types=1);

namespace Unit\Factory;

use Flowpack\ContentSecurityPolicy\Exceptions\InvalidDirectiveException;
use Flowpack\ContentSecurityPolicy\Factory\PolicyFactory;
use Flowpack\ContentSecurityPolicy\Model\Directive;
use Flowpack\ContentSecurityPolicy\Model\Nonce;
use Flowpack\ContentSecurityPolicy\Model\Policy;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(PolicyFactory::class)]
#[UsesClass(Policy::class)]
#[UsesClass(Directive::class)]
#[UsesClass(InvalidDirectiveException::class)]
class PolicyFactoryTest extends TestCase
{
    public function testCreateShouldReturnPolicyAndMergeCustomWithDefaultDirective(): void
    {
        $policyFactory = new PolicyFactory();
        $nonceMock = $this->createMock(Nonce::class);

        $defaultDirective = [
            'base-uri' => [
                'test.com',
            ],
            'script-src' => [
                'test.com',
            ],
        ];
        $customDirective = [
            'script-src' => [
                'custom.com',
            ],
        ];

        $expected = [
            'base-uri' => [
                'test.com',
            ],
            'script-src' => [
                'test.com',
                'custom.com',
            ],
        ];

        $result = $policyFactory->create($nonceMock, $defaultDirective, $customDirective);

        self::assertSame($expected, $result->getDirectives());
    }

    public function testCreateShouldReturnPolicyAndHandleSpecialDirectives(): void
    {
        $policyFactory = new PolicyFactory();
        $nonceMock = $this->createMock(Nonce::class);

        $defaultDirective = [
            'script-src' => [
                '{nonce}',
                'self',
            ],
        ];
        $customDirective = [];

        $expected = [
            'script-src' => [
                "'nonce-'",
                "'self'",
            ],
        ];

        $result = $policyFactory->create($nonceMock, $defaultDirective, $customDirective);

        self::assertSame($expected, $result->getDirectives());
    }

    public function testCreateShouldFailWithInvalidDirective(): void
    {
        $policyFactory = new PolicyFactory();
        $nonceMock = $this->createMock(Nonce::class);

        $defaultDirective = [
            'invalid' => [
                'self',
            ],
            'script-src' => [
                'self',
            ],
        ];
        $customDirective = [];

        $this->expectException(InvalidDirectiveException::class);
        $policyFactory->create($nonceMock, $defaultDirective, $customDirective);
    }

    public function testCreateShouldReturnPolicyWithUniqueValues(): void
    {
        $policyFactory = new PolicyFactory();
        $nonceMock = $this->createMock(Nonce::class);

        $defaultDirective = [
            'base-uri' => [
                'test.com',
            ],
            'script-src' => [
                'test.com',
            ],
        ];
        $customDirective = [
            'base-uri' => [
                'test.com',
                'test.com',
            ],
            'script-src' => [
                'test.com',
            ],
        ];

        $expected = [
            'base-uri' => [
                'test.com',
            ],
            'script-src' => [
                'test.com',
            ],
        ];

        $result = $policyFactory->create($nonceMock, $defaultDirective, $customDirective);

        self::assertSame($expected, $result->getDirectives());
    }

    public function testCreateShouldAddDirectiveWhichIsPresentInCustomButNotDefaultConfiguration(): void
    {
        $policyFactory = new PolicyFactory();
        $nonceMock = $this->createMock(Nonce::class);

        $defaultDirective = [
            'base-uri' => [
                'test.com',
            ],
            'script-src' => [
                'test.com',
            ],
        ];
        $customDirective = [
            'worker-src' => [
                'test.com',
            ],
        ];

        $expected = [
            'base-uri' => [
                "test.com",
            ],
            'script-src' => [
                "test.com",
            ],
            'worker-src' => [
                "test.com",
            ],
        ];

        $result = $policyFactory->create($nonceMock, $defaultDirective, $customDirective);

        self::assertSame($expected, $result->getDirectives());
    }
}
