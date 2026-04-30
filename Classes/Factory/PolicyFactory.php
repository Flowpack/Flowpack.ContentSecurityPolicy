<?php

declare(strict_types=1);

namespace Flowpack\ContentSecurityPolicy\Factory;

use Flowpack\ContentSecurityPolicy\Exceptions\DirectivesNormalizerException;
use Flowpack\ContentSecurityPolicy\Exceptions\InvalidDirectiveException;
use Flowpack\ContentSecurityPolicy\Helpers\DirectivesNormalizer;
use Flowpack\ContentSecurityPolicy\Model\Nonce;
use Flowpack\ContentSecurityPolicy\Model\Policy;
use Neos\Flow\Annotations as Flow;
use Psr\Log\LoggerInterface;

/**
 * @Flow\Scope("singleton")
 */
class PolicyFactory
{
    /**
     * @Flow\InjectConfiguration(path="throw-exception-on-configuration-error")
     */
    protected bool $throwExceptionOnConfigurationError;

    /**
     * @Flow\Inject
     */
    protected LoggerInterface $logger;

    /**
     * @Flow\Inject
     *
     */

    /**
     * @param array<string, array<int|string, mixed>|null> $defaultDirectives
     * @param array<string, array<int|string, mixed>|null> $customDirectives
     * @throws InvalidDirectiveException
     * @throws DirectivesNormalizerException
     */
    public function create(Nonce $nonce, array $defaultDirectives, array $customDirectives): Policy
    {
        $normalizedDefaultDirectives = DirectivesNormalizer::normalize($defaultDirectives);
        $normalizedCustomDirectives = DirectivesNormalizer::normalize($customDirectives);

        $resultDirectives = $normalizedDefaultDirectives;
        foreach ($normalizedCustomDirectives as $key => $customDirective) {
            if (array_key_exists($key, $resultDirectives)) {
                $resultDirectives[$key] = array_merge($resultDirectives[$key], $customDirective);
            } else {
                // Custom directive is not present in default, still needs to be added.
                $resultDirectives[$key] = $customDirective;
            }
            $resultDirectives[$key] = array_unique($resultDirectives[$key]);
        }

        $policy = new Policy();
        $policy->setNonce($nonce);

        foreach ($resultDirectives as $directive => $values) {
            try {
                $policy->addDirective($directive, $values);
            } catch (InvalidDirectiveException $exception) {
                if ($this->throwExceptionOnConfigurationError) {
                    // For development we want to make sure directives are configured correctly.
                    throw $exception;
                } else {
                    // In production we just log the error and continue. If a directive is invalid, we still
                    // want to apply the rest of the policy.
                    $this->logger->critical($exception->getMessage());
                    continue;
                }
            }
        }

        return $policy;
    }
}
