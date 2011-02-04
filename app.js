/**
 * Simple combo handler using NodeJS and Express. Stick a caching and
 * compressing proxy in front of this and you're ready to rock in production.
 *
 * Copyright (c) 2011 Ryan Grove <ryan@wonko.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

var express = require('express'),
    fs      = require('fs'),
    combo   = require('./lib/combohandler');

app = express.createServer();

app.configure(function () {
  app.use(express.conditionalGet());
});

app.configure('development', function () {
  app.use(express.logger());
  app.use(express.errorHandler({
    dumpExceptions: true,
    showStack     : true,
  }));
});

app.configure('production', function () {
  app.use(express.errorHandler());
});

for (var route in combo.config.roots) {
  (function () {
    // Intentionally using the sync method because this only runs once on
    // startup, and we want it to throw if there's an error.
    var root = fs.realpathSync(combo.config.roots[route]);

    app.get(route, function (req, res) {
      combo.combine(root, req, res);
    });
  }());
}

module.exports = app;
