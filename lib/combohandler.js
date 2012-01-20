var fs   = require('fs'),
    path = require('path'),
    util = require('util'),

    // Default set of MIME types supported by the combo handler. Attempts to
    // combine one or more files with an extension not in this mapping (or not
    // in a custom mapping) will result in a 400 response.
    MIME_TYPES = exports.MIME_TYPES = {
        '.css' : 'text/css',
        '.js'  : 'application/javascript',
        '.json': 'application/json',
        '.txt' : 'text/plain',
        '.xml' : 'application/xml'
    };

// -- Exported Methods ---------------------------------------------------------
exports.combine = function (config) {
    var mimeTypes = config.mimeTypes || MIME_TYPES,

        maxAge = config.maxAge || 31536000000, // one year in milliseconds

        // Intentionally using the sync method because this only runs when the
        // middleware is initialized, and we want it to throw if there's an error.
        rootPath = fs.realpathSync(config.rootPath);

    function getMimeType(filename) {
        return mimeTypes[path.extname(filename).toLowerCase()];
    }

    return function (req, res, next) {
        var body    = [],
            query   = parseQuery(req.url),
            pending = query.length,
            type    = pending && getMimeType(query[0]),
            lastModified;

        function finish() {
            if (lastModified) {
                res.header('Last-Modified', lastModified.toUTCString());
            }

            // http://code.google.com/speed/page-speed/docs/caching.html
            res.header('Cache-Control', 'public, max-age=' + (maxAge / 1000));
            res.header('Expires', new Date(Date.now() + maxAge).toUTCString());

            res.header('Content-Type', (type || 'text/plain') + ';charset=utf-8');
            res.body = body.join('\n');

            next();
        }

        if (!pending) {
            // No files requested.
            return next(new BadRequest('No files requested.'));
        }

        query.forEach(function (relativePath, i) {
            // Skip empty parameters.
            if (!relativePath) {
                pending -= 1;
                return;
            }

            var absolutePath = path.normalize(path.join(rootPath, relativePath));

            // Bubble up an error if the request attempts to traverse above the
            // root path.
            if (!absolutePath || absolutePath.indexOf(rootPath) !== 0) {
                return next(new BadRequest('File not found: ' + relativePath));
            }

            fs.stat(absolutePath, function (err, stats) {
                if (err || !stats.isFile()) {
                    return next(new BadRequest('File not found: ' + relativePath));
                }

                var mtime = new Date(stats.mtime);

                if (!lastModified || mtime > lastModified) {
                    lastModified = mtime;
                }

                fs.readFile(absolutePath, 'utf8', function (err, data) {
                    if (err) { return next(new BadRequest('Error reading file: ' + relativePath)); }

                    body[i]  = data;
                    pending -= 1;

                    if (pending === 0) {
                        finish();
                    }
                }); // fs.readFile
            }); // fs.stat
        }); // forEach
    };
};

// BadRequest is used for all filesystem-related errors, including when a
// requested file can't be found (a NotFound error wouldn't be appropriate in
// that case since the route itself exists; it's the request that's at fault).
function BadRequest(message) {
    Error.call(this);
    this.name = 'BadRequest';
    this.message = message;
    Error.captureStackTrace(this, arguments.callee);
}
util.inherits(BadRequest, Error);
exports.BadRequest = BadRequest; // exported to allow instanceof checks

// -- Private Methods ----------------------------------------------------------
function decode(string) {
    return decodeURIComponent(string).replace(/\+/g, ' ');
}

// Because querystring.parse() is silly and tries to be too clever.
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
