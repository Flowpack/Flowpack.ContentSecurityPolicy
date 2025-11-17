<?php

declare(strict_types=1);

namespace Flowpack\ContentSecurityPolicy\Factory;

use Flowpack\ContentSecurityPolicy\Exceptions\InvalidDirectiveException;
use Flowpack\ContentSecurityPolicy\Model\Nonce;
use Flowpack\ContentSecurityPolicy\Model\Policy;
use Neos\Flow\Annotations as Flow;

/**
 * @Flow\Scope("singleton")
 */
class PolicyFactory
{
    /**
     * @param string[][] $defaultDirectives
     * @param string[][] $customDirectives
     * @throws InvalidDirectiveException
     */
    public function create(Nonce $nonce, array $defaultDirectives, array $customDirectives): Policy
    {
        $resultDirectives = $defaultDirectives;
        foreach ($customDirectives as $key => $customDirective) {
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
            $policy->addDirective($directive, $values);
        }

        return $policy;
    }
}
