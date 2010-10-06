#!/usr/bin/env node
/**
 * Simple YUI combo handler using NodeJS and Express. Stick a caching and
 * compressing proxy in front of this and you're ready to rock in production.
 *
 * Copyright (c) 2010 Ryan Grove <ryan@wonko.com>
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
    path    = require('path'),

    config  = require('./config');

// -- Express app and middleware -----------------------------------------------
app = express.createServer(
  // express.logger(),
  express.conditionalGet()
);

// -- Routes -------------------------------------------------------------------
for (var route in config.roots) {
  (function () {
    // Intentionally using the sync method because this only runs once on
    // startup, and we want it to throw if there's an error.
    var root = fs.realpathSync(config.roots[route]);

    app.get(route, function (req, res) {
      comboHandler(root, req, res);
    });
  }());
}

// -- Functions ----------------------------------------------------------------
function comboHandler(rootPath, req, res) {
  var body    = [],
      query   = parseQuery(req.url),
      pending = query.length,
      type    = pending && getMimeType(query[0]),
      lastModified,

  finish = function () {
    if (lastModified) {
      res.header('Last-Modified', lastModified.toUTCString());
    }

    res.send(body.join("\n"), {
      'Content-Type': type + ';charset=utf-8'
    });
  },

  notFound = function () {
    res.send(400);
  };

  if (!pending) {
    return notFound();
  }

  query.forEach(function (relativePath, i) {
    var absolutePath;

    // Skip empty params.
    if (!relativePath) {
      pending -= 1;
      return;
    }

    absolutePath = path.normalize(path.join(rootPath, relativePath));

    fs.realpath(absolutePath, function(err, absolutePath) {
      // Don't allow traversal above the root path.
      if (err || absolutePath.indexOf(rootPath) !== 0) {
        res.send(403); // TODO: nicer error handling
        return;
      }

      fs.readFile(absolutePath, 'utf8', function (err, data) {
        if (err) { return notFound(); }

        body[i] = data;

        fs.stat(absolutePath, function (err, stats) {
          var mtime;

          if (!err) {
            mtime = new Date(stats.mtime);

            if (!lastModified || mtime > lastModified) {
              lastModified = mtime;
            }
          }

          pending -= 1;

          if (pending === 0) {
            finish();
          }
        });
      });
    });
  });
}

function decode(string) {
  return decodeURIComponent(string).replace(/\+/g, ' ');
}

function getMimeType(filename) {
  return config.mimeTypes[path.extname(filename).toLowerCase()];
}

// Because querystring.parse() is stupid.
function parseQuery(url) {
  var parsed = [],
      query  = url.split('?')[1];

  if (query) {
    query.split('&').forEach(function (item) {
      parsed.push(decode(item.split('=')[0]));
    });
  }

  return parsed;
}

app.listen(config.port || 8000);
