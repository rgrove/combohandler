var fs   = require('fs'),
    path = require('path'),
    sys  = require('sys'),

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

      res.header('Content-Type', (type || 'text/plain') + ';charset=utf-8');
      res.body = body.join("\n");

      next();
    }

    function onReadFile(i, err, data) {
      if (err) { return next(new BadRequest); }

      body[i]  = data;
      pending -= 1;

      if (pending === 0) {
        finish();
      }
    }

    function onRealPath(i, err, absolutePath) {
      // Bubble up an error if the file can't be found or if the request
      // attempts to traverse above the root path.
      if (err || !absolutePath || absolutePath.indexOf(rootPath) !== 0) {
        return next(new BadRequest);
      }

      fs.stat(absolutePath, onStat.bind(null, absolutePath, i));
    }

    function onStat(absolutePath, i, err, stats) {
      if (err || !stats.isFile()) { return next(new BadRequest); }

      var mtime = new Date(stats.mtime);

      if (!lastModified || mtime > lastModified) {
        lastModified = mtime;
      }

      fs.readFile(absolutePath, 'utf8', onReadFile.bind(null, i));
    }

    if (!pending) {
      // No files requested.
      return next(new BadRequest);
    }

    query.forEach(function (relativePath, i) {
      // Skip empty parameters.
      if (!relativePath) {
        pending -= 1;
        return;
      }

      fs.realpath(path.normalize(path.join(rootPath, relativePath)),
          onRealPath.bind(null, i));
    });
  };
};

// -- Custom Errors ------------------------------------------------------------
function BadRequest(message) {
  this.name = 'BadRequest';
  Error.call(this, message || 'Bad request.');
  Error.captureStackTrace(this, arguments.callee);
}
sys.inherits(BadRequest, Error);

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

/**
Like Function.bind, but appends the supplied arguments to the end of the
arguments list when calling the bound function, instead of prepending them to
the beginning.

@method rbind
@param {Function} fn Function to bind.
@param {Object} [thisArg] Object to be used as the `this` object when calling
    the bound function.
@param {mixed} [args*] Arguments to append to the arguments provided to the
    bound function when called.
@return {Function} Bound function.
**/
function rbind() {
    var args    = Array.prototype.slice.call(arguments),
        fn      = args.shift(),
        thisArg = args.shift();

    return function () {
        fn.apply(thisArg, Array.prototype.slice.call(arguments).concat(args));
    };
}

