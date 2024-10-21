<?php

declare(strict_types=1);

namespace Flowpack\ContentSecurityPolicy\Exceptions;

use Neos\Flow\Exception;

class InvalidDirectiveException extends Exception
{
    public function __construct(string $invalidDirective)
    {
        parent::__construct(
            "Invalid directive '{$invalidDirective}' provided. Please check your settings.",
        );
    }
}
