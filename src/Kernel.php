<?php
/**
 * Created by PhpStorm.
 * User: Łukasz Biały 
 * URL: http://keios.eu
 * Date: 6/17/15
 * Time: 12:59 PM
 */

namespace Keios\OctoberCsrf;

use Illuminate\Foundation\Http\Kernel as HttpKernel;

class Kernel extends HttpKernel
{

    /**
     * The bootstrap classes for the application.
     *
     * @var array
     */
    protected $bootstrappers = [
        'October\Rain\Foundation\Bootstrap\RegisterClassLoader',
        'Illuminate\Foundation\Bootstrap\DetectEnvironment',
        'October\Rain\Foundation\Bootstrap\LoadConfiguration',
        'October\Rain\Foundation\Bootstrap\LoadTranslation',
        'October\Rain\Foundation\Bootstrap\ConfigureLogging',
        'October\Rain\Foundation\Bootstrap\HandleExceptions', // requires november/snow @ 1c9cf5f6
        'Illuminate\Foundation\Bootstrap\RegisterFacades',
        'October\Rain\Foundation\Bootstrap\RegisterOctober',
        'Illuminate\Foundation\Bootstrap\RegisterProviders',
        'Illuminate\Foundation\Bootstrap\BootProviders',
    ];

    /**
     * The application's global HTTP middleware stack.
     *
     * @var array
     */
    protected $middleware = [
        'Illuminate\Foundation\Http\Middleware\CheckForMaintenanceMode',
        'Illuminate\Cookie\Middleware\EncryptCookies',
        'Illuminate\Cookie\Middleware\AddQueuedCookiesToResponse',
        'Illuminate\Session\Middleware\StartSession',
        'Illuminate\View\Middleware\ShareErrorsFromSession',
        'Keios\OctoberCsrf\VerifyCsrfToken',
    ];

    /**
     * The application's route middleware.
     *
     * @var array
     */
    protected $routeMiddleware = [
        // 'auth' => 'App\Http\Middleware\Authenticate',
        // 'auth.basic' => 'Illuminate\Auth\Middleware\AuthenticateWithBasicAuth',
        // 'guest' => 'App\Http\Middleware\RedirectIfAuthenticated',
    ];

}
