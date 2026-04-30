<?php

declare(strict_types=1);

namespace Flowpack\ContentSecurityPolicy\Http;

use Flowpack\ContentSecurityPolicy\Exceptions\DirectivesNormalizerException;
use Flowpack\ContentSecurityPolicy\Exceptions\InvalidDirectiveException;
use Flowpack\ContentSecurityPolicy\Factory\PolicyFactory;
use Flowpack\ContentSecurityPolicy\Helpers\TagHelper;
use Flowpack\ContentSecurityPolicy\Model\Nonce;
use Flowpack\ContentSecurityPolicy\Model\Policy;
use GuzzleHttp\Psr7\Utils;
use InvalidArgumentException;
use Neos\Flow\Annotations as Flow;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Log\LoggerInterface;

class CspHeaderMiddleware implements MiddlewareInterface
{
    private const NONCE = 'nonce';

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
     * @var array<string, array<string, array<string|int, string|bool>>>
     */
    protected array $configuration;

    /**
     * @Flow\InjectConfiguration(path="policies")
     * @var array<string, array<string, list<string>>>
     */
    protected array $policies;

    /**
     * @Flow\InjectConfiguration(path="throw-exception-on-configuration-error")
     */
    protected bool $throwExceptionOnConfigurationError;

    /**
     * @Flow\Inject
     */
    protected LoggerInterface $logger;

    /**
     * @inheritDoc
     * @throws InvalidDirectiveException
     * @throws DirectivesNormalizerException
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $response = $handler->handle($request);
        if (!$this->enabled) {
            return $response;
        }

        $policy = $this->getPolicyByCurrentContext($request);

        if ($policy->hasNonceDirectiveValue()) {
            $body = $response->getBody();
            $newBody = $this->addNonceToTags((string)$body);
            $body = Utils::streamFor($newBody);
            $response = $response->withBody($body);
        }

        return $response->withAddedHeader($policy->getSecurityHeaderKey(), (string)$policy);
    }

    /**
     * @throws InvalidDirectiveException
     * @throws DirectivesNormalizerException
     */
    private function getPolicyByCurrentContext(ServerRequestInterface $request): Policy
    {
        $path = $request->getUri()->getPath();

        $backendUris = array_merge(
            $this->policies['backend']['matchUris'] ?? [],
            $this->policies['custom-backend']['matchUris'] ?? []
        );

        foreach ($backendUris as $pattern) {
            $result = preg_match('#' . str_replace('#', '\#', $pattern) . '#', $path);
            if ($result === false) {
                $message = sprintf('Invalid matchUri pattern "%s": %s', $pattern, preg_last_error_msg());
                if ($this->throwExceptionOnConfigurationError) {
                    throw new InvalidArgumentException($message);
                }
                $this->logger->critical($message);
                continue;
            }
            if ($result === 1) {
                return $this->policyFactory->create(
                    $this->nonce,
                    $this->configuration['backend'],
                    $this->configuration['custom-backend']
                );
            }
        }

        return $this->policyFactory->create(
            $this->nonce,
            $this->configuration['default'],
            $this->configuration['custom']
        );
    }


    private function addNonceToTags(string $markup): string
    {
        $tagNames = ['script', 'style'];

        return $this->checkTagAndReplaceUsingACallback($tagNames, $markup, function (
            $tagMarkup,
        ): string {
            if (TagHelper::tagHasAttribute($tagMarkup, self::NONCE)) {
                return TagHelper::tagChangeAttributeValue($tagMarkup, self::NONCE, $this->nonce->getValue());
            }

            return TagHelper::tagAddAttribute($tagMarkup, self::NONCE, $this->nonce->getValue());
        });
    }

    /**
     * @param string[] $tagNames
     */
    private function checkTagAndReplaceUsingACallback(
        array $tagNames,
        string $contentMarkup,
        callable $hitCallback
    ): string {
        $regex = '/<(' . implode('|', $tagNames) . ').*?>/';

        return preg_replace_callback(
            $regex,
            function ($hits) use ($hitCallback) {
                $tagMarkup = $hits[0];
                $tagName = $hits[1];

                return call_user_func(
                    $hitCallback,
                    $tagMarkup,
                    $tagName
                );
            },
            $contentMarkup
        );
    }
}
