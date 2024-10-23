<?php

declare(strict_types=1);

namespace Flowpack\ContentSecurityPolicy\Model;

use Exception;
use Neos\Flow\Annotations as Flow;

/**
 * @Flow\Scope("singleton")
 */
class Nonce
{
    private const NONCE_LENGTH = 16;

    private readonly string $value;

    /**
     * @throws Exception
     */
    public function __construct()
    {
        $this->value = $this->generateNonce();
    }

    public function getValue(): string
    {
        return $this->value;
    }

    public function __toString(): string
    {
        return $this->getValue();
    }

    /**
     * @throws Exception
     */
    private function generateNonce(): string
    {
        $string = '';

        while (($currentLength = strlen($string)) < self::NONCE_LENGTH) {
            $size = 16 - $currentLength;

            $bytes = random_bytes($size);

            $string .= substr(str_replace(['/', '+', '='], '', base64_encode($bytes)), 0, $size);
        }

        return $string;
    }
}
