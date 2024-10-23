<?php

declare(strict_types=1);

namespace Flowpack\ContentSecurityPolicy\Model;

use Flowpack\ContentSecurityPolicy\Exceptions\InvalidDirectiveException;
use Neos\Flow\Annotations as Flow;

class Policy
{
    private const SECURITY_HEADER_KEY_REPORT_ONLY = 'Content-Security-Policy-Report-Only';

    private const SECURITY_HEADER_KEY = 'Content-Security-Policy';

    private const SPECIAL_DIRECTIVES = [
        'none',
        'report-sample',
        'self',
        'strict-dynamic',
        'unsafe-eval',
        'unsafe-inline',
    ];

    /**
     * @Flow\InjectConfiguration(path="report-only")
     */
    protected bool $reportOnly;

    private array $directives = [];

    private readonly Nonce $nonce;

    private bool $hasNonceDirectiveValue = false;

    public function setNonce(Nonce $nonce): Policy
    {
        $this->nonce = $nonce;

        return $this;
    }

    public function getSecurityHeaderKey(): string
    {
        if ($this->reportOnly) {
            return self::SECURITY_HEADER_KEY_REPORT_ONLY;
        }

        return self::SECURITY_HEADER_KEY;
    }

    public function getDirectives(): array
    {
        return $this->directives;
    }

    public function hasNonceDirectiveValue(): bool
    {
        return $this->hasNonceDirectiveValue;
    }

    /**
     * @param  string[]  $values
     * @throws InvalidDirectiveException
     */
    public function addDirective(string $directive, array $values): self
    {
        if (! Directive::isValidDirective($directive)) {
            throw new InvalidDirectiveException($directive);
        }
        $this->directives[$directive] = array_map(function ($value) use ($directive) {
            return $this->sanitizeValue($value);
        }, $values);

        return $this;
    }

    public function __toString(): string
    {
        $directives = $this->getDirectives();
        $keys = array_keys($directives);

        $items = array_map(function ($values, $directive) {
            $value = implode(' ', $values);

            return "$directive $value";
        }, $directives, $keys);

        return implode('; ', $items).';';
    }

    private function sanitizeValue(string $value): string
    {
        if (in_array($value, self::SPECIAL_DIRECTIVES)) {
            return "'$value'";
        }

        if ($value === '{nonce}') {
            $this->hasNonceDirectiveValue = true;

            return "'nonce-".$this->nonce->getValue()."'";
        }

        return $value;
    }
}
