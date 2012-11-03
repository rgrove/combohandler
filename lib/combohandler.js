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
    var maxAge    = config.maxAge,
        mimeTypes = config.mimeTypes || MIME_TYPES,

        // Intentionally using the sync method because this only runs when the
        // middleware is initialized, and we want it to throw if there's an
        // error.
        rootPath = fs.realpathSync(config.rootPath);

    if (typeof maxAge === 'undefined') {
        maxAge = 31536000; // one year in seconds
    }

    return function (req, res, next) {
        var body    = [],
            query   = parseQuery(req.url),
            pending = query.length,
            fileTypes = getFileTypes(query),
            // fileTypes array should always have one member, else error
            type    = fileTypes.length === 1 && mimeTypes[fileTypes[0]],
            lastModified;

        function finish() {
            if (lastModified) {
                res.header('Last-Modified', lastModified.toUTCString());
            }

            // http://code.google.com/speed/page-speed/docs/caching.html
            if (maxAge !== null) {
                res.header('Cache-Control', 'public,max-age=' + maxAge);
                res.header('Expires', new Date(Date.now() + (maxAge * 1000)).toUTCString());
            }

            res.header('Content-Type', (type || 'text/plain') + ';charset=utf-8');
            res.body = body.join('\n');

            next();
        }

        if (!pending) {
            // No files requested.
            return next(new BadRequest('No files requested.'));
        }

        if (!type) {
            if (fileTypes.indexOf('') > -1) {
                // Most likely a malformed URL, which will just cause
                // an exception later. Short-cut to the inevitable conclusion.
                return next(new BadRequest('Truncated query parameters.'));
            }
            else if (fileTypes.length === 1) {
                // unmapped type found
                return next(new BadRequest('Illegal MIME type present.'));
            }
            else {
                // A request may only have one MIME type
                return next(new BadRequest('Only one MIME type allowed per request.'));
            }
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

/**
Dedupes an array of strings, returning an array that's guaranteed to contain
only one copy of a given string.

@method dedupe
@param {String[]} array Array of strings to dedupe.
@return {Array} Deduped copy of _array_.
**/
function dedupe(array) {
    var hash    = {},
        results = [],
        hasOwn  = Object.prototype.hasOwnProperty,
        i, item, len;

    for (i = 0, len = array.length; i < len; i += 1) {
        item = array[i];

        if (!hasOwn.call(hash, item)) {
            hash[item] = 1;
            results.push(item);
        }
    }

    return results;
}

function getExtName(filename) {
    return path.extname(filename).toLowerCase();
}

function getFileTypes(files) {
    return dedupe(files.map(getExtName));
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
