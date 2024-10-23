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
     * @param  string[][]  $defaultDirective
     * @param  string[][]  $customDirective
     * @throws InvalidDirectiveException
     */
    public function create(Nonce $nonce, array $defaultDirective, array $customDirective): Policy
    {
        $directiveCollections = [$defaultDirective, $customDirective];
        $defaultDirective = array_shift($directiveCollections);

        array_walk($defaultDirective, function (array &$item, string $key) use ($directiveCollections) {
            foreach ($directiveCollections as $collection) {
                if (array_key_exists($key, $collection)) {
                    $item = array_unique([...$item, ...$collection[$key]]);
                }
            }
        });

        $policy = new Policy();
        $policy->setNonce($nonce);

        foreach ($defaultDirective as $directive => $values) {
            $policy->addDirective($directive, $values);
        }

        return $policy;
    }
}
