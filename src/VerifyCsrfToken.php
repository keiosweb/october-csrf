<?php namespace Keios\OctoberCsrf;

use Closure;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Logging\Log;
use Illuminate\Foundation\Application;
use Symfony\Component\HttpFoundation\Cookie;
use Illuminate\Contracts\Encryption\Encrypter;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Session\TokenMismatchException;

class VerifyCsrfToken
{
    /**
     * The encrypter implementation.
     *
     * @var \Illuminate\Contracts\Encryption\Encrypter
     */
    protected $encrypter;

    /**
     * The event dispatcher implementation.
     *
     * @var \Illuminate\Contracts\Events\Dispatcher
     */
    protected $dispatcher;

    /**
     * @var \Illuminate\Contracts\Logging\Log
     */
    protected $logger;

    /**
     * @var Application
     */
    protected $app;

    /**
     * The URIs that should be excluded from CSRF verification.
     *
     * @var array
     */
    protected $except = [];

    /**
     * Create a new middleware instance.
     *
     * @param  \Illuminate\Foundation\Application         $app
     * @param  \Illuminate\Contracts\Encryption\Encrypter $encrypter
     * @param  \Illuminate\Contracts\Events\Dispatcher    $dispatcher
     * @param  \Illuminate\Contracts\Logging\Log          $logger
     * @param  \Illuminate\Contracts\Config\Repository    $config
     */
    public function __construct(Application $app, Encrypter $encrypter, Dispatcher $dispatcher, Log $logger, Repository $config)
    {
        $this->app = $app;
        $this->encrypter = $encrypter;
        $this->dispatcher = $dispatcher;
        $this->logger = $logger;
        $this->config = $config;

        $this->except[] = $this->config->get('cms.backendUri').'/cms';
        $this->except[] = $this->config->get('cms.backendUri').'/cms/media';
    }

    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request $request
     * @param  \Closure $next
     * @return mixed
     *
     * @throws \Illuminate\Session\TokenMismatchException
     */
    public function handle($request, Closure $next)
    {
        $this->dispatcher->fire('kernel.middleware.csrf', [$this]);

        if ($this->isReading($request) ||
            $this->runningUnitTests() ||
            $this->shouldPassThrough($request) ||
            $this->tokensMatch($request)
        ) {
            return $this->addCookieToResponse($request, $next($request));
        }

        throw new TokenMismatchException;
    }

    /**
     * Determine if the application is running unit tests.
     *
     * @return bool
     */
    protected function runningUnitTests()
    {
        return $this->app->runningInConsole() && $this->app->runningUnitTests();
    }

    /**
     * Allow dynamic whitelist definition.
     *
     * @param $path
     * @return void
     */
    public function whitelist($path)
    {
        $this->except[] = $path;
    }

    /**
     * Determine if the request has a URI that should pass through CSRF verification.
     *
     * @param  \Illuminate\Http\Request $request
     * @return bool
     */
    protected function shouldPassThrough($request)
    {
        foreach ($this->except as $except) {
            if ($except !== '/') {
                $except = trim($except, '/');
            }

            if ($request->is($except)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Determine if the session and input CSRF tokens match.
     *
     * @param  \Illuminate\Http\Request $request
     * @return bool
     */
    protected function tokensMatch($request)
    {
        $sessionToken = $request->session()->token();

        $token = $request->input('_token') ?: $request->header('X-CSRF-TOKEN');

        if (!$token && $header = $request->header('X-XSRF-TOKEN')) {
            try {
                $token = $this->encrypter->decrypt($header);
            } catch (\Exception $ex) {
                $request->session()->flush();
                $this->logger->error('Intercepted invalid data exception during CSRF verification. Session was flushed.');
            }
        }

        if (!is_string($sessionToken) || !is_string($token)) {
            return false;
        }

	    return hash_equals($sessionToken, $token);
    }

    /**
     * Add the CSRF token to the response cookies.
     *
     * @param  \Illuminate\Http\Request $request
     * @param  \Illuminate\Http\Response $response
     * @return \Illuminate\Http\Response
     */
    protected function addCookieToResponse($request, $response)
    {
        $config = config('session');

        $response->headers->setCookie(
            new Cookie(
                'XSRF-TOKEN', $request->session()->token(), time() + 60 * $config['lifetime'],
                $config['path'], $config['domain'], $config['secure'], false
            )
        );

        return $response;
    }

    /**
     * Determine if the HTTP request uses a ‘read’ verb.
     *
     * @param  \Illuminate\Http\Request $request
     * @return bool
     */
    protected function isReading($request)
    {
        return in_array($request->method(), ['HEAD', 'GET', 'OPTIONS']);
    }
}


