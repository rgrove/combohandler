Combo Handler
=============

[![Build Status](https://travis-ci.org/rgrove/combohandler.png?branch=master)](https://travis-ci.org/rgrove/combohandler)

This is a simple combo handler for Node.js, usable either as [Connect][]
middleware or as an [Express][] server. It works just like the combo handler
service on the Yahoo! CDN, which you'll be familiar with if you've used YUI.

The combo handler is compatible with the [YUI][] Loader, so you can use it to
host YUI, or you can use it with any other JavaScript or CSS if you're willing
to construct the combo URLs yourself.

The combo handler itself doesn't perform any caching or compression, but stick
[Nginx][] or something in front of it and you should be ready to rock in
production.

[Connect]: https://github.com/senchalabs/connect
[Express]: https://github.com/visionmedia/express
[Nginx]: http://nginx.org/
[YUI]: http://yuilibrary.com/


Installation
------------

Install using npm:

```bash
npm install combohandler
```

Or just clone the [GitHub repo](https://github.com/rgrove/combohandler):

```bash
git clone git://github.com/rgrove/combohandler.git
```


Usage
-----

The `combohandler` module provides a configurable Connect middleware that can be
used to add combo handling capability to any Connect-based request handler (like
Express).

The `combohandler/lib/server` module creates a standalone Express server instance,
or augments an existing server, to perform combo handling for a set of
configurable routes.


### As Express middleware

The combo handler middleware can be used as application-wide middleware for all
routes:

```js
var combo = require('combohandler');
app.use(combo.combine({rootPath: '/local/path/to/files'}));
```

Or as route middleware for a specific route:

```js
app.get('/foo', combo.combine({rootPath: '/local/path/to/foo'}), combo.respond);
```

In either case, the middleware will perform combo handling for files under the
specified local `rootPath` when requested using a URL with one or more file paths
in the query string:

```text
http://example.com/<route>?<path>[&path][...]
```

For example:

```text
http://example.com/foo?file1.js
http://example.com/foo?file1.js&file2.js
http://example.com/foo?file1.js&file2.js&subdir/file3.js
```

Attempts to traverse above the `rootPath` or to request a file that doesn't
exist will result in a `BadRequest` error being bubbled up.

Here's a basic Express app that uses the combo handler as route middleware for
multiple routes with different root paths:

```js
var combo   = require('combohandler'),
    express = require('express'),

    app = express();

app.configure(function () {
  app.use(express.errorHandler());
});

// Return a 400 response if the combo handler generates a BadRequest error.
app.use(combo.errorHandler());

// Given a root path that points to a YUI 3 root folder, this route will
// handle URLs like:
//
// http://example.com/yui3?build/yui/yui-min.js&build/loader/loader-min.js
//
app.get('/yui3', combo.combine({rootPath: '/local/path/to/yui3'}), combo.respond);

app.listen(3000);
```

#### `combo.respond`

The `respond` method exported by `require('combohandler')` is a convenience
method intended to be the last callback passed to an
[express route](http://expressjs.com/api.html#app.VERB).
Unless you have a *very* good reason to avoid it, you should probably use it.
Here is the equivalent callback:

```js
function respond(req, res) {
    res.send(res.body);
}
```

This method may be extended in the future to do fancy things with optional
combohandler middleware.

#### `combo.errorHandler`

The `errorHandler` export encapsulates the convention of sending `BadRequest`
errors with an optional `errorMaxAge` config.
By default, `BadRequest` errors are served with a 5 minute `max-age` header.

To explicitly disable caching (via
`Pragma: no-cache` and
`Cache-Control: private,no-store`
headers), pass `null` in the options object:

```js
app.use(combo.errorHandler({
    errorMaxAge: null
}));
```

Any other value (including zero) for `errorMaxAge` is interpreted as the
desired duration in seconds.

### Creating a server

If you just want to get a server up and running quickly by specifying a mapping
of routes to local root paths, use the `combohandler/lib/server` module.
It creates a barebones Express server that will perform combo handling on the
routes you specify:

```js
var comboServer = require('combohandler/lib/server'),
    app;

app = comboServer({
    roots: {
        '/yui3': '/local/path/to/yui3'
    }
});

app.listen(3000);
```

### Augmenting an existing server

If you already have an existing Express server instance and just want to add
some combo handled routes to it easily, you can augment your existing server
with combo handled routes:

```js
var comboServer = require('combohandler/lib/server');

comboServer({
    roots: {
        '/yui3': '/local/path/to/yui3'
    }
}, myApp); // Assuming `myApp` is a pre-existing Express server instance.
```

### From the command line

If installed globally via `npm -g install`,
the CLI executable `combohandler` is provided.
If you're operating from a local clone,
`npm link` in the repository root and you're off to the races.
To start the default single-process server,
it's as simple as

```bash
combohandler
# combohandler now running until you hit Ctrl+C
```

Of course, the default output leaves something to be desired: that is to say,
any output.

#### Root Configuration

At the very least,
you need to provide some route-to-rootPath mappings for your CLI combohandler.

When passed in the `--rootsFile` option,
the JSON file contents should follow this pattern:

```json
{
    "/yui3": "/local/path/to/yui3"
}
```

When passed as individual `--root` parameters,
the equivalent to the JSON above looks like this:

```bash
combohandler --root /yui3:/local/path/to/yui3 [...]
```

To run the standalone server in production mode, set the `NODE_ENV` variable to
`production` before running it:

```bash
    NODE_ENV=production combohandler --root /yui3:/path/to/yui3
```

#### CLI Usage

```text
Usage: combohandler [options]

General Options:
  -h, --help        Output this text
  -v, --version     Prints combohandler's version

Combine Options:
  -p, --port        Port to listen on.                                    [8000]
  -a, --server      Script that exports an Express app [combohandler/lib/server]
  -r, --root        String matching the pattern '{route}:{rootPath}'.
                        You may pass any number of unique --root configs.
  -f, --rootsFile   Path to JSON routes config, *exclusive* of --root.
  -b, --basePath    URL path to prepend when rewriting relative url()s.     ['']
  -w, --webRoot     Filesystem path to base rewritten relative url()s from. ['']
                    Use this instead of --basePath when using route parameters.
                    Overrides behaviour of --basePath.
  -m, --maxAge      'Cache-Control' and 'Expires' value, in seconds.  [31536000]
                    Set this to `0` to expire immediately, `null` to omit these
                    headers entirely.

Cluster Options:
  --cluster         Enable clustering of server across multiple processes.
  -d, --pids        Directory where pidfiles are stored.       [$PREFIX/var/run]
  -n, --workers     Number of worker processes.          [os.cpus.length, max 8]
  -t, --timeout     Timeout (in ms) for process startup/shutdown.         [5000]

  --restart         Restart a running master's worker processes.       (SIGUSR2)
  --shutdown        Shutdown gracefully, allows connections to close.  (SIGTERM)
  --status          Logs status of master and workers.
  --stop            Stop server abruptly, not waiting for connections. (SIGKILL)
```

The `--port` and `--server` options may also be set via npm package config settings:

```bash
npm -g config set combohandler:port 2702
npm -g config set combohandler:server /path/to/server.js
```

Unlike the `--server` option, a path specified in this manner *must* be absolute.

### Clustered!

With the advent of `node` v0.8.x, the core `cluster` module is now usable,
and `combohandler` now regains the capability it once had.
Huzzah! said the villagers.

To run a clustered combohandler from the CLI, just add the `--cluster` flag:

```bash
combohandler --cluster --root /yui3:/path/to/yui3
```

To clusterize combohandler from a module dependency,
`combohandler/lib/cluster` is your friend:

```js
var comboCluster = require('combohandler/lib/cluster');
var app = comboCluster({
    pids: '/path/to/piddir',
    server: './myserver.js',
    roots: {
        '/yui3': '/local/path/to/yui3'
    }
});
app.listen(2702);
```

Optional Middleware
-------------------

### Rewriting URLs in CSS files

Because the combo handler changes the path from which CSS files are loaded,
relative URLs in CSS files need to be updated to be relative to the
combohandled path.
Set the `basePath` or `webRoot` configuration option to have the
combohandler default middleware do this automatically.

```js
// This static route can be used to load images and other assets that shouldn't
// be combined.
//
app.use('/public', express.static(__dirname + '/public'));

// This route will combine requests for files in the public directory, and will
// also automatically rewrite relative paths in CSS files to point to the
// non-combohandled static route defined above.
//
app.get('/combo', combo.combine({
    rootPath: __dirname + '/public',
    basePath: '/public'
}), combo.respond);

// The equivalent config as the previous route, except using webRoot
app.get('/combo', combo.combine({
    rootPath: __dirname + '/public',
    webRoot : __dirname
}), combo.respond);
```

Alternatively, you can use the built-in `cssUrls` middleware as a separate
route callback. `cssUrls` must always be placed after the default `combine`
middleware when used in this fashion.

```js
// This route provides the same behaviour as the previous example, providing
// better separation of concerns and the possibility of inserting custom
// middleware between the built-in steps.
app.get('/combo',
    combo.combine({
        rootPath: __dirname + '/public'
    }),
    combo.cssUrls({
        basePath: '/public'
    }),
    combo.respond);
```

Finally, the `cssUrls` middleware has the ability (disabled by default) to
rewrite `@import` paths in the same manner as `url()` values. As `@import` is
considered an anti-pattern in production code, this functionality is strictly
opt-in and requires passing `true` as the `rewriteImports` property in the
middleware options object.

```js
// Automagically
app.get('/combo', combo.combine({
    rootPath: __dirname + '/public',
    webRoot : __dirname,
    rewriteImports: true
}), combo.respond);

// As explicit middleware
app.get('/combo',
    combo.combine({ rootPath: __dirname + '/public' }),
    combo.cssUrls({ basePath: '/public', rewriteImports: true }),
    combo.respond);
```

#### `basePath` or `webRoot`?

In the simplest case,
`basePath` and `webRoot` reach the same result from different directions.
`basePath` allows you to rewrite a single well-known path under any root,
whereas `webRoot` will handle any number of paths under a well-known root.

In general, if you are using both optional middleware,
you should prefer `webRoot` over `basePath`.

### Dynamic Paths via Route Parameters

To enable resolution of dynamic subtree paths under a given `rootPath`,
simply add a [route parameter](http://expressjs.com/api.html#req.params)
to both the route and the `rootPath` config.

```js
app.get('/combo/yui/:version', combo.combine({
    rootPath: '/local/path/to/yui/:version/build'
}), combo.respond);
```

Given this config,
any [YUI release tarball](http://yuilibrary.com/download/yui3/) you explode
into a versioned subdirectory of `/local/path/to/yui/` would be available
under a much shorter URL than the default config provides:

```text
    http://example.com/combo/yui/3.9.1?yui/yui-min.js&yui-throttle/yui-throttle-min.js
    // vs
    http://example.com/combo/yui?3.9.1/build/yui/yui-min.js&3.9.1/build/yui-throttle/yui-throttle-min.js
```

If the built-in `dynamicPath` middleware is used manually, it _must_ be
inserted *before* the default `combine` middleware.


Using as a YUI 3 combo handler
------------------------------

With a tiny bit of configuration, you can tell YUI to use your custom combo
handler instead of the Yahoo! combo handler. Here's an example:

```html
<script src="http://example.com/combo/yui3?build/yui/yui-min.js"></script>
<script>
YUI({
    comboBase: 'http://example.com/combo/yui3?',
    combine  : true,
    root     : 'build/'
}).use('node', function (Y) {
    // YUI will now automatically load modules from the custom combo handler.
});
</script>
```


License
-------

Copyright (c) 2012 Yahoo! Inc. All rights reserved.

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
