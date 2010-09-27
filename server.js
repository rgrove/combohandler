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

    // Port to listen on.
    PORT = 80,

    // Absolute path to the public YUI3 directory.
    YUI3_PATH = '/home/node/public/yui/yui3',

    app = express.createServer(
        // express.logger(),
        express.conditionalGet()
    );

// -- Routes -------------------------------------------------------------------
app.get('/yui3', function (req, res) {
    var body    = [],
        query   = parseQuery(req.url) || [],
        pending = query.length,
        type    = pending && getMimeType(path.extname(query[0])),

        lastModified;

    function finish() {
        if (lastModified) {
            res.header('Last-Modified', lastModified.toUTCString());
        }

        res.send(body.join("\n"), {
            'Content-Type': type + ';charset=utf-8'
        });
    }

    function notFound() {
        res.send(400);
    }

    query.forEach(function (relativePath, i) {
        var absolutePath;

        // Skip empty params.
        if (!relativePath) {
            pending -= 1;
            return;
        }

        absolutePath = path.normalize(path.join(YUI3_PATH, relativePath));

        // Don't allow traversal above the root path.
        if (absolutePath.indexOf(YUI3_PATH) !== 0) {
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

// -- Helpers ------------------------------------------------------------------
var defaultMimeType = 'application/octet-stream',

    mimeTypes = {
        '.css' : 'text/css',
        '.js'  : 'application/javascript',
        '.json': 'application/json',
        '.txt' : 'text/plain',
        '.xml' : 'application/xml'
    };

function decode(string) {
    return decodeURIComponent(string).replace(/\+/g, ' ');
}

function getMimeType(extension) {
    extension = (extension.charAt(0) === '.' ? extension : '.' + extension).toLowerCase();
    return mimeTypes[extension] || defaultMimeType;
}

// Because querystring.parse() is stupid.
function parseQuery(query) {
    var parsed = [];

    query.split('?')[1].split('&').forEach(function (item) {
        parsed.push(decode(item.split('=')[0]));
    });

    return parsed;
}

app.listen(PORT);
