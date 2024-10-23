<?php

declare(strict_types=1);

namespace Unit\Model;

use Flowpack\ContentSecurityPolicy\Model\Nonce;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(Nonce::class)]
class NonceTest extends TestCase
{
    public function testGetValueShouldReturnRandomNonceValues(): void
    {
        $testRunCount = 10000;
        $randomStrings = [];

        for ($i = 0; $i < $testRunCount; $i++) {
            $nonce = new Nonce();
            $randomString = (string)$nonce;

            self::assertSame(16, strlen($randomString));
            $randomStrings[] = $randomString;
        }

        self::assertTrue(array_unique($randomStrings) === $randomStrings, 'Random generator not sufficient');
    }
}
