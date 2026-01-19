<?php

declare(strict_types=1);

namespace Flowpack\ContentSecurityPolicy\Helpers;

use Flowpack\ContentSecurityPolicy\Exceptions\DirectivesNormalizerException;
use Psr\Log\LoggerInterface;

/**
 * Helper to support normalization of directives from different formats.
 * The old format supported yaml lists. Now key-value pairs should be used for directives.
 * In the future we will deprecate the list format!
 *
 * We also cleanup of empty directives and entries here before further processing.
 */
final class DirectivesNormalizer
{
    /**
     * @param array<string, ?array<string|int, string|bool>> $directives
     * @return string[][]
     * @throws DirectivesNormalizerException
     */
    public static function normalize(array $directives, LoggerInterface $logger): array
    {
        $result = [];
        // directives e.g. script-src:
        foreach ($directives as $directive => $values) {
            if (!is_array($values) || count($values) === 0) {
                continue;
            }

            $normalizedValues = [];
            $firstKeyType = null;
            // values e.g. 'self', 'unsafe-inline' OR key-value pairs e.g. example.com: true
            foreach ($values as $key => $value) {
                if ($firstKeyType === null) {
                    $firstKeyType = gettype($key);
                } else {
                    if (gettype($key) !== $firstKeyType) {
                        // we do not allow mixed key types -> this should be marked as an error in the IDE as well
                        // as Flow should throw an exception here. But just to be sure, we add this check.
                        throw new DirectivesNormalizerException(
                            'Directives must be defined as a list OR an object.'
                        );
                    }
                }

                if (is_int($key) && is_string($value) && trim($value) !== '') {
                    // old configuration format using list
                    $normalizedValues[] = $value;
                    $logger->warning(
                        'Using list format for CSP directives is deprecated and will be removed in future versions. Please use key-value pairs with boolean values instead.'
                    );
                } elseif (is_string($key)) {
                    // new configuration format using key-value pairs
                    if (is_bool($value)) {
                        if ($value === true && trim($key) !== '') {
                            $normalizedValues[] = $key;
                        }
                        continue;
                    }

                    // We chose a format similar to NodeType constraints yaml configuration.
                    throw new DirectivesNormalizerException(
                        'When using keys in your yaml, the values must be boolean.'
                    );
                }
            }
            if ($normalizedValues !== []) {
                // we also clean up empty directives here
                $result[$directive] = $normalizedValues;
            }
        }

        return $result;
    }
}
