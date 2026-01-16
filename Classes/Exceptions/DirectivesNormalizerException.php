<?php

declare(strict_types=1);

namespace Flowpack\ContentSecurityPolicy\Exceptions;

use Neos\Flow\Exception;

class DirectivesNormalizerException extends Exception
{
    public function __construct(string $reason)
    {
        parent::__construct(
            "Invalid yaml config provided. {$reason} Please check your settings.",
        );
    }
}
