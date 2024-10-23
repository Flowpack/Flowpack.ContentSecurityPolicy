<?php

declare(strict_types=1);

namespace Unit\Helpers;

use Flowpack\ContentSecurityPolicy\Helpers\TagHelper;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(TagHelper::class)]
class TagHelperTest extends TestCase
{
    public function testTagHasAttributeWithoutValueShouldReturnTrue(): void
    {
        $tag = '<script src="https://google.com"></script>';
        self::assertTrue(TagHelper::tagHasAttribute($tag, 'src'));
    }

    public function testTagHasAttributeWithoutValueShouldReturnFalse(): void
    {
        $tag = '<script src="https://google.com"></script>';
        self::assertFalse(TagHelper::tagHasAttribute($tag, 'bar'));
    }

    public function testTagHasAttributeWithValueShouldReturnTrue(): void
    {
        $tag = '<script src="https://google.com"></script>';
        self::assertTrue(TagHelper::tagHasAttribute($tag, 'src', 'https://google.com'));
    }

    public function testTagHasAttributeWithValueShouldReturnFalse(): void
    {
        $tag = '<script src="https://google.com"></script>';
        self::assertFalse(TagHelper::tagHasAttribute($tag, 'src', 'another value'));
    }

    public function testTagChangeAttributeValueShouldChangeValue(): void
    {
        $tag = '<script src="https://google.com"></script>';

        self::assertSame(
            '<script src="https://test.com"></script>',
            TagHelper::tagChangeAttributeValue($tag, 'src', 'https://test.com')
        );
    }

    public function testTagChangeAttributeValueShouldDoNothingIfAttributeDoesntExist(): void
    {
        $tag = '<script src="https://google.com"></script>';

        self::assertSame(
            '<script src="https://google.com"></script>',
            TagHelper::tagChangeAttributeValue($tag, 'nonce', 'da65sf1g')
        );
    }

    public function testTagAddAttributeShouldAddAttributeWithValue(): void
    {
        $tag = '<script src="https://google.com"></script>';

        self::assertSame(
            '<script src="https://google.com" nonce="da65sf1g"></script>',
            TagHelper::tagAddAttribute($tag, 'nonce', 'da65sf1g')
        );
    }

    public function testTagAddAttributeShouldAddAttributeWithoutValue(): void
    {
        $tag = '<script src="https://google.com"></script>';

        self::assertSame(
            '<script src="https://google.com" defer></script>',
            TagHelper::tagAddAttribute($tag, 'defer')
        );
    }
}
