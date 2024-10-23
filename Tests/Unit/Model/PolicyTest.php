<?php

declare(strict_types=1);

namespace Unit\Model;

use Flowpack\ContentSecurityPolicy\Exceptions\InvalidDirectiveException;
use Flowpack\ContentSecurityPolicy\Model\Directive;
use Flowpack\ContentSecurityPolicy\Model\Nonce;
use Flowpack\ContentSecurityPolicy\Model\Policy;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use ReflectionClass;

#[CoversClass(Policy::class)]
#[CoversClass(InvalidDirectiveException::class)]
#[UsesClass(Directive::class)]
class PolicyTest extends TestCase
{
    private readonly Policy $policy;
    private readonly ReflectionClass $policyReflection;

    protected function setUp(): void
    {
        parent::setUp();

        $this->policy = new Policy();
        $nonceMock = $this->createMock(Nonce::class);
        $this->policy->setNonce($nonceMock);

        $this->policyReflection = new ReflectionClass($this->policy);
        $this->policyReflection->getProperty('reportOnly')->setValue($this->policy, false);
    }

    public function testGetSecurityHeaderKeyWithReportOnlyEnabled(): void
    {
        $this->policyReflection->getProperty('reportOnly')->setValue($this->policy, true);

        self::assertSame(
            'Content-Security-Policy-Report-Only',
            $this->policy->getSecurityHeaderKey()
        );
    }

    public function testGetSecurityHeaderKeyWithReportOnlyDisabled(): void
    {
        self::assertSame(
            'Content-Security-Policy',
            $this->policy->getSecurityHeaderKey()
        );
    }

    public function testAddDirectiveShouldFailWithInvalidDirective(): void
    {
        $this->expectException(InvalidDirectiveException::class);

        $this->policy->addDirective('invalid-directive', ['bar']);
    }

    public function testAddDirectiveShouldAddSpecialDirective(): void
    {
        $this->policy->addDirective('script-src', ['self',]);

        self::assertSame(
            [
                'script-src' => ["'self'"],
            ],
            $this->policy->getDirectives()
        );
    }

    public function testAddDirectiveShouldDetectNonceDirective(): void
    {
        $this->policy->addDirective('script-src', ['self', '{nonce}']);

        self::assertSame(
            [
                'script-src' => ["'self'", "'nonce-'"],
            ],
            $this->policy->getDirectives()
        );

        self::assertTrue($this->policy->hasNonceDirectiveValue());
    }

    public function testAddDirectiveShouldAddNonSpecialDirective(): void
    {
        $this->policy->addDirective('script-src', ['https://foo.bar']);

        self::assertSame(
            [
                'script-src' => ['https://foo.bar'],
            ],
            $this->policy->getDirectives()
        );
    }

    public function testToString(): void
    {
        $this->policy->addDirective('script-src', ['https://foo.bar']);
        $this->policy->addDirective('style-src', ['https://foo.bar']);

        self::assertSame(
            'script-src https://foo.bar; style-src https://foo.bar;',
            (string)$this->policy
        );
    }
}
