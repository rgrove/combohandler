module.exports = {
    // Mapping of URL paths to local filesystem paths. Each URL defined here
    // will become a combo handler for files under the specified local
    // directory.
    //
    // You can then make combo-handled requests to these paths, like:
    //
    //   http://example.com/yui3?build/yui/yui-min.js&build/loader/loader-min.js
    //
    // The :version placeholder is used to version the combo-handled requests by
    // "global" directory name (usually a sha1 hash), instead of per-file.
    //
    // The URL and local path must both contain the placeholder ":version"
    //
    //   http://example.com/84b94bb/combo?build/mod-a/mod-a-min.js&build/mod-b/mod-b-min.js
    //     resolves to:
    //       /local/path/to/84b94bb/build/mod-a/mod-a-min.js
    //       /local/path/to/84b94bb/build/mod-b/mod-b-min.js
    roots: {
        '/:version/combo': '/local/path/to/:version',
        '/yui3': '/local/path/to/yui3'
    },

    // Maximum age in seconds to send in the `Cache-Control` and `Expires`
    // response headers. Set this to `0` to cause immediate expiration, or
    // `null` to prevent the `Cache-Control` and `Expires` headers from being
    // set.
    //
    // The default value is 31536000 seconds, or 1 year.
    maxAge: 31536000
};
