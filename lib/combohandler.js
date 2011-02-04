var config = require('../config'),
    fs     = require('fs'),
    path   = require('path');

// -- Exported Properties ------------------------------------------------------
exports.config = config;

// -- Exported Methods ---------------------------------------------------------
exports.combine = function (rootPath, req, res) {
  var body    = [],
      query   = parseQuery(req.url),
      pending = query.length,
      type    = pending && getMimeType(query[0]),
      lastModified;

  function finish() {
    if (lastModified) {
      res.header('Last-Modified', lastModified.toUTCString());
    }

    res.send(body.join("\n"), {
      'Content-Type': (type || 'text/plain') + ';charset=utf-8'
    });
  }

  function onReadFile(i, err, data) {
    if (err) { return httpServerError(res); }

    body[i] = data;
    pending -= 1;

    if (pending === 0) {
      finish();
    }
  }

  function onRealPath(i, err, absolutePath) {
    // Return an HTTP 400 Bad Request error when the file can't be found or when
    // the request attempts to traverse above the root path.
    if (err || !absolutePath || absolutePath.indexOf(rootPath) !== 0) {
      return httpBadRequest(res);
    }

    fs.stat(absolutePath, onStat.bind(null, absolutePath, i));
  }

  function onStat(absolutePath, i, err, stats) {
    if (err || !stats.isFile()) { return httpBadRequest(res); }

    var mtime = new Date(stats.mtime);

    if (!lastModified || mtime > lastModified) {
      lastModified = mtime;
    }

    fs.readFile(absolutePath, 'utf8', onReadFile.bind(null, i));
  }

  if (!pending) {
    return httpBadRequest(res);
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

// -- Private Methods ----------------------------------------------------------

function decode(string) {
  return decodeURIComponent(string).replace(/\+/g, ' ');
}

function getMimeType(filename) {
  return config.mimeTypes[path.extname(filename).toLowerCase()];
}

function httpBadRequest(res) {
  res.writeHead(400, {'Content-Type': 'text/plain;charset=utf-8'});
  res.end('Bad Request');
}

function httpServerError(res) {
  res.writeHead(500, {'Content-Type': 'text/plain;charset=utf-8'});
  res.end('Internal Server Error');
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
