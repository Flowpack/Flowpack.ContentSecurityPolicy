<?php

declare(strict_types=1);

namespace Flowpack\ContentSecurityPolicy\Helpers;

class TagHelper
{
    public static function tagHasAttribute(
        string $tag,
        string $name,
        string $value = null
    ): bool {
        $value = (string)$value;
        if ($value === '') {
            return (bool)preg_match(
                self::buildMatchAttributeNameReqex($name),
                $tag
            );
        }

        return (bool)preg_match(
            self::buildMatchAttributeNameWithSpecificValueReqex(
                $name,
                $value
            ),
            $tag
        );
    }

    public static function tagChangeAttributeValue(
        string $tag,
        string $name,
        string $newValue
    ): string {
        return preg_replace_callback(
            self::buildMatchAttributeNameWithAnyValueReqex($name),
            function ($hits) use ($newValue) {
                return $hits["pre"].
                    $hits["name"].
                    $hits["glue"].
                    $newValue.
                    $hits["post"];
            },
            $tag
        );
    }

    public static function tagAddAttribute(
        string $tag,
        string $name,
        string $value = null
    ): string {
        return preg_replace_callback(
            self::buildMatchEndOfOpeningTagReqex(),
            function ($hits) use ($name, $value) {
                if ((string)$value !== '') {
                    return $hits["start"].
                        ' '.
                        $name.
                        '="'.
                        $value.
                        '"'.
                        $hits["end"];
                }

                return $hits["start"].' '.$name.$hits["end"];
            },
            $tag
        );
    }

    private static function escapeReqexCharsInString(string $value): string
    {
        // for some reason "/" is not escaped
        return str_replace("/", "\/", preg_quote($value));
    }

    private static function buildMatchEndOfOpeningTagReqex(): string
    {
        return '/(?<start><[a-z]+.*?)(?<end>>|\/>)/';
    }

    private static function buildMatchAttributeNameWithAnyValueReqex(string $name): string
    {
        $nameQuoted = self::escapeReqexCharsInString($name);

        return '/(?<pre><.*? )(?<name>'.
            $nameQuoted.
            ')(?<glue>=")(?<value>.*?)(?<post>".*?>)/';
    }

    private static function buildMatchAttributeNameReqex(string $name): string
    {
        $nameQuoted = self::escapeReqexCharsInString($name);

        return '/(?<pre><.*? )(?<name>'.$nameQuoted.')(?<post>.*?>)/';
    }

    private static function buildMatchAttributeNameWithSpecificValueReqex(
        string $name,
        string $value
    ): string {
        $nameQuoted = self::escapeReqexCharsInString($name);
        $valueQuoted = self::escapeReqexCharsInString($value);

        return '/(?<pre><.*? )(?<name>'.
            $nameQuoted.
            ')(?<glue>=")(?<value>'.
            $valueQuoted.
            ')(?<post>".*?>)/';
    }
}
