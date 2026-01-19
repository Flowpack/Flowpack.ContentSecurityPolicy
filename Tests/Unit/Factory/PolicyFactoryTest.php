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
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use ReflectionClass;

#[CoversClass(PolicyFactory::class)]
#[UsesClass(Policy::class)]
#[UsesClass(Directive::class)]
#[UsesClass(InvalidDirectiveException::class)]
class PolicyFactoryTest extends TestCase
{
    private readonly LoggerInterface&MockObject $loggerMock;
    private readonly PolicyFactory $policyFactory;
    private readonly ReflectionClass $policyFactoryReflection;

    protected function setUp(): void
    {
        parent::setUp();

        $this->loggerMock = $this->createMock(LoggerInterface::class);

        $this->policyFactory = new PolicyFactory();

        $this->policyFactoryReflection = new ReflectionClass($this->policyFactory);
        $this->policyFactoryReflection->getProperty('logger')->setValue($this->policyFactory, $this->loggerMock);
        $this->policyFactoryReflection->getProperty('throwInvalidDirectiveException')->setValue(
            $this->policyFactory,
            true
        );
    }

    public function testCreateShouldReturnPolicyAndMergeCustomWithDefaultDirective(): void
    {
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

        $result = $this->policyFactory->create($nonceMock, $defaultDirective, $customDirective);

        self::assertSame($expected, $result->getDirectives());
    }

    public function testCreateShouldReturnPolicyAndHandleSpecialDirectives(): void
    {
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

        $result = $this->policyFactory->create($nonceMock, $defaultDirective, $customDirective);

        self::assertSame($expected, $result->getDirectives());
    }

    public function testCreateShouldFailWithInvalidDirective(): void
    {
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
        $this->policyFactory->create($nonceMock, $defaultDirective, $customDirective);
    }

    public function testCreateShouldLogInvalidDirectiveInProduction(): void
    {
        $nonceMock = $this->createMock(Nonce::class);
        $this->policyFactoryReflection->getProperty('throwInvalidDirectiveException')->setValue(
            $this->policyFactory,
            false
        );

        $defaultDirective = [
            'invalid' => [
                'self',
            ],
            'script-src' => [
                'self',
            ],
        ];
        $customDirective = [];

        $this->loggerMock->expects($this->once())->method('critical');
        $this->policyFactory->create($nonceMock, $defaultDirective, $customDirective);

        $this->policyFactoryReflection->getProperty('throwInvalidDirectiveException')->setValue(
            $this->policyFactory,
            true
        );
    }

    public function testCreateShouldReturnPolicyWithUniqueValues(): void
    {
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

        $result = $this->policyFactory->create($nonceMock, $defaultDirective, $customDirective);

        self::assertSame($expected, $result->getDirectives());
    }

    public function testCreateShouldAddDirectiveWhichIsPresentInCustomButNotDefaultConfiguration(): void
    {
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

        $result = $this->policyFactory->create($nonceMock, $defaultDirective, $customDirective);

        self::assertSame($expected, $result->getDirectives());
    }
}
