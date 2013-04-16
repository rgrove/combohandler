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

    npm install combohandler

Or just clone the [GitHub repo](https://github.com/rgrove/combohandler):

    git clone git://github.com/rgrove/combohandler.git


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

    http://example.com/<route>?<path>[&path][...]

For example:

    http://example.com/foo?file1.js
    http://example.com/foo?file1.js&file2.js
    http://example.com/foo?file1.js&file2.js&subdir/file3.js

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
app.use(function (err, req, res, next) {
    if (err instanceof combo.BadRequest) {
        res.charset = 'utf-8';
        res.type('text/plain');
        res.send(400, 'Bad request. ' + err.message);
    } else {
        next(err);
    }
});

// Given a root path that points to a YUI 3 root folder, this route will
// handle URLs like:
//
// http://example.com/yui3?build/yui/yui-min.js&build/loader/loader-min.js
//
app.get('/yui3', combo.combine({rootPath: '/local/path/to/yui3'}), combo.respond);

app.listen(3000);
```

#### `combo.respond`

The `respond` method exported by `require('combohandler')` is a convenience method intended to be the last callback passed to an [express route](http://expressjs.com/api.html#app.VERB). Unless you have a *very* good reason to avoid it, you should probably use it. Here is the equivalent callback:

```js
function respond(req, res) {
    res.send(res.body);
}
```

This method may be extended in the future to do fancy things with optional combohandler middleware.

### Creating a server

If you just want to get a server up and running quickly by specifying a mapping
of routes to local root paths, use the `combohandler/lib/server` module. It
creates a barebones Express server that will perform combo handling on the
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

### Running the included standalone server

If you clone or download the GitHub repo, you can rename `config.sample.js` to
`config.js`, edit it to your liking, and then simply run `app.js` to start a
standalone server in development mode on port 8000.

    git clone git://github.com/rgrove/combohandler.git
    cd combohandler
    mv config.sample.js config.js
    ./app.js

To run the standalone server in production mode, set the `NODE_ENV` variable to
`production` before running it:

    NODE_ENV=production ./app.js


### Rewriting URLs in CSS files

Because the combo handler changes the path from which CSS files are loaded,
relative URLs in CSS files need to be updated to be relative to the
combohandled path. Set the `basePath` configuration option to have the combo
handler do this automatically.

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
    basePath: '/public',
    rewriteImports: true
}), combo.respond);

// As explicit middleware
app.get('/combo',
    combo.combine({ rootPath: __dirname + '/public' }),
    combo.cssUrls({ basePath: '/public', rewriteImports: true }),
    combo.respond);
```

### Dynamic Paths via Route Parameters

To enable resolution of dynamic subtree paths under a given `rootPath`, simply add a [route parameter](http://expressjs.com/api.html#req.params) to both the route and the `rootPath` config.

```js
app.get('/combo/yui/:version', combo.combine({
    rootPath: '/local/path/to/yui/:version/build'
}), combo.respond);
```

Given this config, any [YUI release tarball](http://yuilibrary.com/download/yui3/) you explode into a versioned subdirectory of `/local/path/to/yui/` would be available under a much shorter URL than the default config provides:

    http://example.com/combo/yui/3.9.1?yui/yui-min.js&yui-throttle/yui-throttle-min.js
    // vs
    http://example.com/combo/yui?3.9.1/build/yui/yui-min.js&3.9.1/build/yui-throttle/yui-throttle-min.js

If the built-in `dynamicPath` middleware is used manually, it _must_ be inserted *before* the default `combine` middleware.

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
