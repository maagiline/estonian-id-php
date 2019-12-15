<?php

namespace maagiline\EstonianIdPhp;

use Illuminate\Support\ServiceProvider;

class EIDServiceProvider extends ServiceProvider
{
    /**
     * Register bindings in the container.
     *
     * @return void
     */
    public function register()
    {
        if ( fileExists( app_path() . '/config/eid/config.php')) {
          $this->mergeConfigFrom(app_path() . '/config/eid/config.php', 'eid' );
        } else {
          $this->mergeConfigFrom(__DIR__ . '/config/config.php', 'eid' );
        }
    }

    public function boot()
    {
        $this->publishes([
            __DIR__ . '/config' => config_path('eid'),
        ]);
    }
}
