/**
Middleware that rewrites relative url() and import paths into
absolute paths based on config (basePath).
**/
var path = require('path');
var URI  = require("URIjs");

var RX_URL = /:\s*url\(\s*(['"]?)(\S+)\1\s*\)/g;
var RX_IMPORT = /\@import\s*(?:url\(\s*)?(['"]?)(\S+)\1(?:\s*\))?[^;'"]*;/g;

var replacer = function replacer(basePath, relativePath) {
    return function (substr, quote, match) {
        // There is a ton of complexity related to URL parsing related
        // to unicode, escapement, etc. Rather than try to capture that,
        // this just does a simple sniff to validate whether the URL
        // needs to be rewritten.
        if (!URI(match).is("relative")) {
            return substr;
        }

        var fileBasePath = path.join(basePath, relativePath),
            fileDirName  = path.dirname(fileBasePath),
            absolutePath = path.resolve(fileDirName, match);

        return substr.replace(match, absolutePath);
    };
};

/**
Route middleware that rewrites relative paths found in CSS source
url() values absolutized to the configured basePath.

Optionally, @import directives can be similarly processed.

@method cssUrls
@param {Object} options
    @param {String} basePath
    @param {Boolean} [imports=false]
@return {Function}
**/
exports = module.exports = function (options) {
    options = options || {};

    // @import directives are considered an anti-pattern
    // in production code, so this feature is explicitly
    // opt-in only.
    var importsEnabled = (true === options.rewriteImports),
        basePath = options.basePath;

    return function cssUrlsMiddleware(req, res, next) {
        var bodyContents,
            relativePaths;

        if (basePath && isCSS(res)) {
            relativePaths = res.locals.relativePaths;
            bodyContents  = res.locals.bodyContents;

            if (bodyContents && relativePaths) {
                // synchronous replacement
                relativePaths.forEach(function (relativePath, i) {
                    bodyContents[i] = exports.rewrite(basePath, relativePath, bodyContents[i], importsEnabled);
                });

                // overwrites response body with replaced content
                res.body = bodyContents.join('\n');
            }
        }

        next();
    };
};

exports.rewrite = function rewriteCSSURLs(basePath, relativePath, data, importsEnabled) {
    var replaceCallback = replacer(basePath, relativePath);

    if (importsEnabled) {
        data = data.replace(RX_IMPORT, replaceCallback);
    }

    return data.replace(RX_URL, replaceCallback);
};

function isCSS(res) {
    return res.get('Content-Type').indexOf('text/css') > -1;
}
