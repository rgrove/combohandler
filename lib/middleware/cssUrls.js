/**
Middleware that rewrites relative url() and import paths into
absolute paths based on config (basePath).
**/
var path = require('path');
var URI  = require("URIjs");

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

exports.rewrite = function rewriteCSSURLs(basePath, relativePath, data) {
    return data.replace(/[\s:]url\(\s*(['"]?)(\S+)\1\s*\)/g, replacer(basePath, relativePath));
};
