var connect = require('connect'),
    express = require('express'),
    combo   = require('./combohandler');

module.exports = function (config, baseApp) {
  var app   = baseApp || express.createServer(),
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
      if (!connect.utils.modified(req, res)) {
        return connect.utils.notModified(res);
      }

      res.send(res.body, 200);
    });
  }

  return app;
};
