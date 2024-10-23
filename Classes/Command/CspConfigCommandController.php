<?php

declare(strict_types=1);

namespace Flowpack\ContentSecurityPolicy\Command;

use Flowpack\ContentSecurityPolicy\Exceptions\InvalidDirectiveException;
use Flowpack\ContentSecurityPolicy\Factory\PolicyFactory;
use Flowpack\ContentSecurityPolicy\Model\Nonce;
use Flowpack\ContentSecurityPolicy\Model\Policy;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Cli\CommandController;
use Neos\Flow\Cli\Exception\StopCommandException;

class CspConfigCommandController extends CommandController
{
    /**
     * @Flow\InjectConfiguration(path="enabled")
     */
    protected bool $enabled;

    /**
     * @Flow\Inject
     */
    protected Nonce $nonce;

    /**
     * @Flow\Inject
     */
    protected PolicyFactory $policyFactory;

    /**
     * @Flow\InjectConfiguration(path="content-security-policy")
     * @var string[][][]
     */
    protected array $configuration;

    /**
     * Show CSP config
     *
     * Shows the generated config for the CSP.
     * @throws StopCommandException
     */
    public function showCommand(): void
    {
        try {
            $backendPolicy = $this->policyFactory->create(
                $this->nonce,
                $this->configuration['backend'],
                $this->configuration['custom-backend']
            );

            $frontendPolicy = $this->policyFactory->create(
                $this->nonce,
                $this->configuration['default'],
                $this->configuration['custom']
            );
        } catch (InvalidDirectiveException $exception) {
            $this->outputLine(
                sprintf('<error>Invalid directive "%s" in configuration file.</error>', $exception->getMessage())
            );

            $this->quit(1);
        }

        $this->outputLine('<b>Backend CSP</b>');
        $this->printPolicy($backendPolicy);

        $this->outputLine("\n<b>Frontend CSP</b>");
        $this->printPolicy($frontendPolicy);
        $this->quit();
    }

    private function printPolicy(Policy $policy): void
    {
        $directives = $policy->getDirectives();
        $keys = array_keys($directives);

        $items = array_map(function ($values, $directive) {
            $value = implode(', ', $values);

            return "$directive: $value";
        }, $directives, $keys);
        foreach ($items as $item) {
            $this->outputLine($item);
        }
    }
}
