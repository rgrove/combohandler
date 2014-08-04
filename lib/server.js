var combo   = require('./combohandler'),
    merge   = require('./utils').merge,
    logger  = require('morgan'),
    errors  = require('errorhandler'),
    express = require('express');

module.exports = function (config, baseApp) {
    var app   = baseApp || express(),
        env   = process.env.NODE_ENV || 'development',
        roots = (config && config.roots) || {},
        route;

    if (!baseApp) {
        if (env === 'development') {
            app.use(logger('combined'));
            app.use(errors());
        } else if (env === 'test') {
            app.use(errors());
        }
    }

    /*jshint forin:false */
    for (route in roots) {
        // pass along all of config, overwriting rootPath
        app.get(route, combo.combine(merge(config, {rootPath: roots[route]})), combo.respond);
    }

    if (!baseApp) {
        // Express 4.x removes app.router, running all middleware in order
        app.use(combo.errorHandler());
    }

    return app;
};
