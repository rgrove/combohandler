// Port on which to run the server.
exports.port = 8000;

// Mapping of URL paths to local filesystem paths. Each URL defined here will
// become a combo handler for files under the specified local directory.
exports.roots = {
    '/yui2': '/local/path/to/yui2',
    '/yui3': '/local/path/to/yui3'
};

// MIME types supported and recognized by this combo handler. Attempts to combo
// one or more files with an extension not in this mapping will result in a
// 400 response.
exports.mimeTypes = {
  '.css' : 'text/css',
  '.js'  : 'application/javascript',
  '.json': 'application/json',
  '.txt' : 'text/plain',
  '.xml' : 'application/xml'
};
