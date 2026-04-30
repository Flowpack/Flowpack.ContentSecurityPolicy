<?php

declare(strict_types=1);

namespace Flowpack\ContentSecurityPolicy\Tests\Unit\Http;

use Exception;
use Flowpack\ContentSecurityPolicy\Factory\PolicyFactory;
use Flowpack\ContentSecurityPolicy\Helpers\TagHelper;
use Flowpack\ContentSecurityPolicy\Http\CspHeaderMiddleware;
use Flowpack\ContentSecurityPolicy\Model\Nonce;
use Flowpack\ContentSecurityPolicy\Model\Policy;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\UriInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Log\LoggerInterface;
use ReflectionClass;
use Throwable;

use function PHPUnit\Framework\once;

#[CoversClass(CspHeaderMiddleware::class)]
#[UsesClass(TagHelper::class)]
class CspHeaderMiddlewareTest extends TestCase
{
    private readonly CspHeaderMiddleware $middleware;
    private readonly ReflectionClass $middlewareReflection;
    private readonly ServerRequestInterface&MockObject $requestMock;
    private readonly RequestHandlerInterface&MockObject $requestHandlerMock;
    private readonly ResponseInterface&MockObject $responseMock;
    private readonly UriInterface&MockObject $uriMock;
    private readonly PolicyFactory&MockObject $policyFactoryMock;
    private readonly Policy&MockObject $policyMock;
    private readonly LoggerInterface&MockObject $loggerMock;

    /**
     * @throws Throwable
     */
    protected function setUp(): void
    {
        parent::setUp();

        $this->middleware = new CspHeaderMiddleware();

        $this->requestMock = $this->createMock(ServerRequestInterface::class);
        $this->requestHandlerMock = $this->createMock(RequestHandlerInterface::class);
        $this->responseMock = $this->createMock(ResponseInterface::class);
        $nonceMock = $this->createMock(Nonce::class);
        $this->uriMock = $this->createMock(UriInterface::class);
        $this->policyFactoryMock = $this->createMock(PolicyFactory::class);
        $this->policyMock = $this->createMock(Policy::class);
        $this->loggerMock = $this->createMock(LoggerInterface::class);

        $this->middlewareReflection = new ReflectionClass($this->middleware);

        $reflectionProperty = $this->middlewareReflection->getProperty('enabled');
        $reflectionProperty->setValue($this->middleware, true);

        $reflectionProperty = $this->middlewareReflection->getProperty('nonce');
        $reflectionProperty->setValue($this->middleware, $nonceMock);

        $reflectionProperty = $this->middlewareReflection->getProperty('policyFactory');
        $reflectionProperty->setValue($this->middleware, $this->policyFactoryMock);

        $reflectionProperty = $this->middlewareReflection->getProperty('configuration');
        $reflectionProperty->setValue(
            $this->middleware,
            ['backend' => [], 'custom-backend' => [], 'default' => [], 'custom' => [],]
        );

        $reflectionProperty = $this->middlewareReflection->getProperty('policies');
        $reflectionProperty->setValue(
            $this->middleware,
            ['backend' => ['matchUris' => ['^/neos']], 'custom-backend' => ['matchUris' => []]]
        );

        $reflectionProperty = $this->middlewareReflection->getProperty('throwExceptionOnConfigurationError');
        $reflectionProperty->setValue($this->middleware, true);

        $reflectionProperty = $this->middlewareReflection->getProperty('logger');
        $reflectionProperty->setValue($this->middleware, $this->loggerMock);

        $this->requestHandlerMock->expects($this->once())->method('handle')->willReturn($this->responseMock);
    }

    public function testProcessShouldDoNothingIfIsDisabled(): void
    {
        $reflectionProperty = $this->middlewareReflection->getProperty('enabled');
        $reflectionProperty->setValue($this->middleware, false);

        $this->responseMock->expects($this->never())->method('withAddedHeader');

        $this->middleware->process($this->requestMock, $this->requestHandlerMock);
    }

    public function testProcessShouldAddHeadersToResponse(): void
    {
        $this->requestMock->expects($this->once())->method('getUri')->willReturn($this->uriMock);
        $this->uriMock->expects($this->once())->method('getPath')->willReturn('/neos');

        $this->policyFactoryMock->expects($this->once())->method('create')->willReturn($this->policyMock);
        $this->policyMock->expects($this->once())->method('hasNonceDirectiveValue')->willReturn(false);

        $this->responseMock->expects($this->once())->method('withAddedHeader')->willReturnSelf();

        $this->middleware->process($this->requestMock, $this->requestHandlerMock);
    }

    public function testProcessShouldAddHeadersToResponseAndReplaceBody(): void
    {
        $this->requestMock->expects($this->once())->method('getUri')->willReturn($this->uriMock);
        $this->uriMock->expects($this->once())->method('getPath')->willReturn('/neos');

        $this->policyFactoryMock->expects($this->once())->method('create')->willReturn($this->policyMock);

        $this->policyMock->expects($this->once())->method('hasNonceDirectiveValue')->willReturn(true);
        $this->responseMock->expects(once())->method('getBody')->willReturn(
            '<html lang="en"><head><title>Test</title></head></head><body><script nonce="123"></script><script></script></body></html>'
        );

        $this->responseMock->expects($this->once())->method('withBody')->willReturnSelf();
        $this->responseMock->expects($this->once())->method('withAddedHeader')->willReturnSelf();

        $this->middleware->process($this->requestMock, $this->requestHandlerMock);
    }

    public function testProcessShouldUseBackendPolicyForCustomMatchUri(): void
    {
        $reflectionProperty = $this->middlewareReflection->getProperty('policies');
        $reflectionProperty->setValue(
            $this->middleware,
            ['backend' => ['matchUris' => ['^/neos']], 'custom-backend' => ['matchUris' => ['^/monocle(/.*)?$']]]
        );

        $this->requestMock->expects($this->once())->method('getUri')->willReturn($this->uriMock);
        $this->uriMock->expects($this->once())->method('getPath')->willReturn('/monocle/dashboard');

        $this->policyFactoryMock->expects($this->once())->method('create')->willReturn($this->policyMock);
        $this->policyMock->expects($this->once())->method('hasNonceDirectiveValue')->willReturn(false);
        $this->responseMock->expects($this->once())->method('withAddedHeader')->willReturnSelf();

        $this->middleware->process($this->requestMock, $this->requestHandlerMock);
    }

    public function testProcessShouldUseDefaultPolicyWhenNoMatchUriMatches(): void
    {
        $this->requestMock->expects($this->once())->method('getUri')->willReturn($this->uriMock);
        $this->uriMock->expects($this->once())->method('getPath')->willReturn('/monocle/dashboard');

        $this->policyFactoryMock->expects($this->once())->method('create')->willReturn($this->policyMock);
        $this->policyMock->expects($this->once())->method('hasNonceDirectiveValue')->willReturn(false);
        $this->responseMock->expects($this->once())->method('withAddedHeader')->willReturnSelf();

        $this->middleware->process($this->requestMock, $this->requestHandlerMock);
    }

    public function testProcessShouldNotMatchNeosWhenBackendMatchUrisOverridden(): void
    {
        $reflectionProperty = $this->middlewareReflection->getProperty('policies');
        $reflectionProperty->setValue(
            $this->middleware,
            ['backend' => ['matchUris' => ['^/other']], 'custom-backend' => ['matchUris' => []]]
        );

        $this->requestMock->expects($this->once())->method('getUri')->willReturn($this->uriMock);
        $this->uriMock->expects($this->once())->method('getPath')->willReturn('/neos');

        $this->policyFactoryMock->expects($this->once())->method('create')->willReturn($this->policyMock);
        $this->policyMock->expects($this->once())->method('hasNonceDirectiveValue')->willReturn(false);
        $this->responseMock->expects($this->once())->method('withAddedHeader')->willReturnSelf();

        $this->middleware->process($this->requestMock, $this->requestHandlerMock);
    }

    public function testProcessThrowsOnInvalidMatchUriPattern(): void
    {
        $reflectionProperty = $this->middlewareReflection->getProperty('policies');
        $reflectionProperty->setValue(
            $this->middleware,
            ['backend' => ['matchUris' => ['^/neos(']], 'custom-backend' => ['matchUris' => []]]
        );

        $this->requestMock->expects($this->once())->method('getUri')->willReturn($this->uriMock);
        $this->uriMock->expects($this->once())->method('getPath')->willReturn('/neos');

        /*
         * preg_match emmits a warning which makes phpunit fail, so we convert warnings to errors and expect an exception
         * as we cannot expect warnings
         */
        set_error_handler(static function (int $errorCode, string $errorString): never {
            throw new Exception($errorString, $errorCode);
        }, E_WARNING);
        $this->expectExceptionMessage('Compilation failed');

        try {
            $this->middleware->process($this->requestMock, $this->requestHandlerMock);
        } finally {
            restore_error_handler();
        }
    }

    public function testProcessLogsInvalidMatchUriPatternInProduction(): void
    {
        $reflectionProperty = $this->middlewareReflection->getProperty('throwExceptionOnConfigurationError');
        $reflectionProperty->setValue($this->middleware, false);

        $reflectionProperty = $this->middlewareReflection->getProperty('policies');
        $reflectionProperty->setValue(
            $this->middleware,
            ['backend' => ['matchUris' => ['^/neos(']], 'custom-backend' => ['matchUris' => []]]
        );

        $this->requestMock->expects($this->once())->method('getUri')->willReturn($this->uriMock);
        $this->uriMock->expects($this->once())->method('getPath')->willReturn('/neos');

        $this->loggerMock->expects($this->once())->method('critical');
        $this->policyFactoryMock->expects($this->once())->method('create')->willReturn($this->policyMock);
        $this->policyMock->expects($this->once())->method('hasNonceDirectiveValue')->willReturn(false);
        $this->responseMock->expects($this->once())->method('withAddedHeader')->willReturnSelf();

        /*
         * preg_match emmits a warning which makes phpunit fail, so we suppress the warning that would make phpunit
         * fail
         */
        set_error_handler(static function (): bool {
            return true;
        }, E_WARNING);

        try {
            $this->middleware->process($this->requestMock, $this->requestHandlerMock);
        } finally {
            restore_error_handler();
        }
    }
}
