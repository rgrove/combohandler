module.exports = {
  // Mapping of URL paths to local filesystem paths. Each URL defined here will
  // become a combo handler for files under the specified local directory.
  //
  // You can then make combo-handled requests to these paths, like:
  //
  //   http://example.com/yui2?build/yahoo/yahoo-min.js&build/yuiloader/yuiloader-min.js
  //   http://example.com/yui3?build/yui/yui-min.js&build/loader/loader-min.js
  //
  roots: {
    '/yui2': '/local/path/to/yui2',
    '/yui3': '/local/path/to/yui3'
  },

  // MIME types supported and recognized by this combo handler. Attempts to
  // combine one or more files with an extension not in this mapping will result
  // in a 400 response.
  mimeTypes: {
    '.css' : 'text/css',
    '.js'  : 'application/javascript',
    '.json': 'application/json',
    '.txt' : 'text/plain',
    '.xml' : 'application/xml'
  }
};
