var combo   = require('./combohandler'),
    merge   = require('./utils').merge,
    express = require('express');

module.exports = function (config, baseApp) {
    var app   = baseApp || express(),
        roots = (config && config.roots) || {},
        route;

    if (!baseApp) {
        app.configure('development', function () {
            app.use(express.logger());
            app.use(express.errorHandler({
                dumpExceptions: true,
                showStack     : true
            }));
        });

        app.configure('test', function () {
            app.use(express.errorHandler({
                dumpExceptions: true,
                showStack     : true
            }));
        });

        app.configure('production', function () {
            app.use(express.errorHandler());
        });

        app.use(app.router);

        app.use(combo.errorHandler());
    }

    /*jshint forin:false */
    for (route in roots) {
        // pass along all of config, overwriting rootPath
        app.get(route, combo.combine(merge(config, {rootPath: roots[route]})), combo.respond);
    }

    return app;
};
