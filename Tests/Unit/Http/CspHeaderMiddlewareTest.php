<?php

declare(strict_types=1);

namespace Unit\Http;

use Flowpack\ContentSecurityPolicy\Factory\PolicyFactory;
use Flowpack\ContentSecurityPolicy\Helpers\TagHelper;
use Flowpack\ContentSecurityPolicy\Http\CspHeaderMiddleware;
use Flowpack\ContentSecurityPolicy\Model\Nonce;
use Flowpack\ContentSecurityPolicy\Model\Policy;
use Neos\Flow\Security\Exception\InvalidPolicyException;
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
    private readonly ServerRequestInterface|MockObject $requestMock;
    private readonly RequestHandlerInterface|MockObject $requestHandlerMock;
    private readonly ResponseInterface|MockObject $responseMock;
    private readonly LoggerInterface|MockObject $loggerMock;
    private readonly Nonce|MockObject $nonceMock;
    private readonly UriInterface|MockObject $uriMock;
    private readonly PolicyFactory|MockObject $policyFactoryMock;
    private readonly Policy|MockObject $policyMock;

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
        $this->loggerMock = $this->createMock(LoggerInterface::class);
        $this->nonceMock = $this->createMock(Nonce::class);
        $this->uriMock = $this->createMock(UriInterface::class);
        $this->policyFactoryMock = $this->createMock(PolicyFactory::class);
        $this->policyMock = $this->createMock(Policy::class);

        $this->middlewareReflection = new ReflectionClass($this->middleware);

        $reflectionProperty = $this->middlewareReflection->getProperty('logger');
        $reflectionProperty->setValue($this->middleware, $this->loggerMock);

        $reflectionProperty = $this->middlewareReflection->getProperty('enabled');
        $reflectionProperty->setValue($this->middleware, true);

        $reflectionProperty = $this->middlewareReflection->getProperty('nonce');
        $reflectionProperty->setValue($this->middleware, $this->nonceMock);

        $reflectionProperty = $this->middlewareReflection->getProperty('policyFactory');
        $reflectionProperty->setValue($this->middleware, $this->policyFactoryMock);

        $reflectionProperty = $this->middlewareReflection->getProperty('configuration');
        $reflectionProperty->setValue(
            $this->middleware,
            ['backend' => [], 'custom-backend' => [], 'default' => [], 'custom' => [],]
        );

        $this->requestHandlerMock->expects($this->once())->method('handle')->willReturn($this->responseMock);
    }

    public function testProcessShouldDoNothingIfIsDisabled(): void
    {
        $reflectionProperty = $this->middlewareReflection->getProperty('enabled');
        $reflectionProperty->setValue($this->middleware, false);

        $this->responseMock->expects($this->never())->method('withAddedHeader');

        $this->middleware->process($this->requestMock, $this->requestHandlerMock);
    }

    public function testProcessShouldDoNothingIfPolicyIsInvalid(): void
    {
        $this->requestMock->expects($this->once())->method('getUri')->willReturn($this->uriMock);
        $this->uriMock->expects($this->once())->method('getPath')->willReturn('/');

        $this->policyFactoryMock->expects($this->once())->method('create')->willThrowException(
            new InvalidPolicyException()
        );

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
}
