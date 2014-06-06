/**
Middleware that rewrites relative url() and import paths into
absolute paths based on config (basePath).
**/
var path = require('path');
var URI  = require("URIjs");
var memoize = require('../utils').memoize;

var RX_URL = /(?:\@import)?\s*url\(\s*(['"]?)(\S+?)\1\s*\)/g;
var RX_IMPORT = /\@import\s*(?:url\(\s*)?(['"]?)(\S+)\1(?:\s*\))?[^;'"]*;/g;

var replacer = function replacer(basePath, relativePath, importsEnabled) {
    return function (substr, quote, match) {
        if (!substringEligible(substr, match, importsEnabled)) {
            return substr;
        }

        var fileBasePath = path.join(basePath, relativePath),
            fileDirName  = path.dirname(fileBasePath),
            absolutePath = path.resolve(fileDirName, match);

        return substr.replace(match, absolutePath);
    };
};

var substringEligible = memoize(function (substr, match, importsEnabled) {
    // There is a ton of complexity related to URL parsing related
    // to unicode, escapement, etc. Rather than try to capture that,
    // this just does a simple sniff to validate whether the URL
    // needs to be rewritten.
    var enabled = URI(match).is("relative");

    if (enabled && substr.indexOf('@import') > -1) {
        enabled = importsEnabled;
    }

    return enabled;
});

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
    var importsEnabled = (true === options.rewriteImports);
    var basePath = options.basePath;
    var webRoot = options.webRoot;
    var enabled = !!(basePath || webRoot);

    return function cssUrlsMiddleware(req, res, next) {
        var relativePaths = res.locals.relativePaths;
        var bodyContents  = res.locals.bodyContents;

        if (enabled && !!(relativePaths && bodyContents) && isCSS(res)) {
            var opts = {
                "basePath": basePath,
                "importsEnabled": importsEnabled
            };

            if (webRoot) {
                // rebase rootPath to webRoot, creates "absolutely relative" pathname
                opts.basePath = path.normalize(
                    path.resolve(webRoot, res.locals.rootPath)
                        .replace(webRoot, path.sep)
                );
            }

            // synchronous replacement
            relativePaths.forEach(function (relativePath, i) {
                bodyContents[i] = exports.rewrite(bodyContents[i], relativePath, opts);
            });

            // overwrites response body with replaced content
            res.body = bodyContents.join('\n');
        }

        next();
    };
};

exports.rewrite = function rewriteCSSURLs(data, relativePath, opts) {
    var basePath = opts.basePath;
    var importsEnabled = opts.importsEnabled;

    var replaceCallback = replacer(basePath, relativePath, importsEnabled);

    if (importsEnabled) {
        data = data.replace(RX_IMPORT, replaceCallback);
    }

    return data.replace(RX_URL, replaceCallback);
};

function isCSS(res) {
    var contentType = res.get('Content-Type');
    return contentType && contentType.indexOf('text/css') > -1;
}
