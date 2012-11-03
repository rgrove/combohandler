var combo   = require('./combohandler'),
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

        app.use(function (err, req, res, next) {
            if (err instanceof combo.BadRequest) {
                res.charset = 'utf-8';
                res.type('text/plain');
                res.send(400, 'Bad request. ' + err.message);
            } else {
                next();
            }
        });
    }

    for (route in roots) {
        app.get(route, combo.combine({rootPath: roots[route]}), function (req, res) {
            res.send(res.body);
        });
    }

    return app;
};
