var express = require('express'),
    fs      = require('fs'),
    combo   = require('../index');

module.exports = function (config, baseApp) {
  var app   = baseApp || express.createServer(),
      roots = (config && config.roots) || {},
      route;

  if (!baseApp) {
    app.configure(function () {
      app.use(express.conditionalGet());
    });

    app.configure('development', function () {
      app.use(express.logger());
      app.use(express.errorHandler({
        dumpExceptions: true,
        showStack     : true
      }));
    });

    app.configure('production', function () {
      app.use(express.errorHandler());
    });

    app.error(function (err, req, res, next) {
      if (err instanceof combo.BadRequest) {
        res.send('Bad request.', {'Content-Type': 'text/plain'}, 400);
      } else {
        next();
      }
    });
  }

  for (route in roots) {
    app.get(route, combo.combine({rootPath: roots[route]}), function (req, res) {
      res.send(res.body, 200);
    });
  }

  return app;
};
