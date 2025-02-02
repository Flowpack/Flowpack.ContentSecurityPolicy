<?php

declare(strict_types=1);

namespace Flowpack\ContentSecurityPolicy\Http;

use Exception;
use Flowpack\ContentSecurityPolicy\Exceptions\InvalidDirectiveException;
use Flowpack\ContentSecurityPolicy\Factory\PolicyFactory;
use Flowpack\ContentSecurityPolicy\Helpers\TagHelper;
use Flowpack\ContentSecurityPolicy\Model\Nonce;
use Flowpack\ContentSecurityPolicy\Model\Policy;
use GuzzleHttp\Psr7\Utils;
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
    protected LoggerInterface $logger;

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
     * @inheritDoc
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $response = $handler->handle($request);
        if (! $this->enabled) {
            return $response;
        }

        try {
            $policy = $this->getPolicyByCurrentContext($request);
        } catch (Exception $exception) {
            $this->logger->critical($exception->getMessage(), ['exception' => $exception]);

            return $response;
        }

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
     */
    private function getPolicyByCurrentContext(ServerRequestInterface $request): Policy
    {
        /*
         * There is no other way to know if we're in the backend here, we cannot inject
         * Neos\Neos\Domain\Service\ContentContext at this point as it throws an error.
         */
        if (str_starts_with($request->getUri()->getPath(), '/neos')) {
            return $this->policyFactory->create(
                $this->nonce,
                $this->configuration['backend'],
                $this->configuration['custom-backend']
            );
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
     * @param  string[]  $tagNames
     */
    private function checkTagAndReplaceUsingACallback(
        array $tagNames,
        string $contentMarkup,
        callable $hitCallback
    ): string {
        $regex = '/<('.implode('|', $tagNames).').*?>/';

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
