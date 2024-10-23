<?php

declare(strict_types=1);

namespace Unit\Factory;

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
class PolicyFactoryTest extends TestCase
{
    public function testCreateShouldReturnPolicy(): void
    {
        $policyFactory = new PolicyFactory();
        $nonceMock = $this->createMock(Nonce::class);

        $defaultDirective = [
            'base-uri' => [
                'self',
            ],
            'script-src' => [
                'self',
            ],
        ];
        $customDirective = [
            'script-src' => [
                '{nonce}',
            ],
        ];

        $expected = [
            'base-uri' => [
                "'self'",
            ],
            'script-src' => [
                "'self'",
                "'nonce-'",
            ],
        ];

        $result = $policyFactory->create($nonceMock, $defaultDirective, $customDirective);

        self::assertSame($expected, $result->getDirectives());
    }
}
