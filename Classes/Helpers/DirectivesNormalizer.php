<?php

declare(strict_types=1);

namespace Flowpack\ContentSecurityPolicy\Helpers;

use Flowpack\ContentSecurityPolicy\Exceptions\DirectivesNormalizerException;

/**
 * Normalizes CSP directives from yaml key-value pairs (e.g. example.com: true) to string arrays.
 * Also removes empty directives and entries before further processing.
 */
final class DirectivesNormalizer
{
    /**
     * @param array<string, array<int|string, mixed>|null> $directives
     * @return string[][]
     * @throws DirectivesNormalizerException
     */
    public static function normalize(array $directives): array
    {
        $result = [];
        foreach ($directives as $directive => $values) {
            if (!is_array($values) || count($values) === 0) {
                continue;
            }

            $normalizedValues = [];
            foreach ($values as $key => $value) {
                if (!is_string($key)) {
                    throw new DirectivesNormalizerException(
                        'Directives must be defined as an object with string keys and boolean values.'
                    );
                }

                if (!is_bool($value)) {
                    throw new DirectivesNormalizerException(
                        'When using keys in your yaml, the values must be boolean.'
                    );
                }

                if ($value === true && trim($key) !== '') {
                    $normalizedValues[] = $key;
                }
            }

            if ($normalizedValues !== []) {
                $result[$directive] = $normalizedValues;
            }
        }

        return $result;
    }
}
