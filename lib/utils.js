/**
Shared Utilities
**/
var fs = require('fs');
var path = require('path');

exports.mix = mix;
exports.merge = merge;
exports.memoize = memoize;
exports.resolvePathSync = resolvePathSync;

function mix(receiver, supplier) {
    if (supplier) {
        Object.keys(supplier).forEach(function (k) {
            receiver[k] = supplier[k];
        });
    }

    return receiver;
}

function merge() {
    var result = {};

    ([].slice.call(arguments)).forEach(function (obj) {
        mix(result, obj);
    });

    return result;
}

function memoize(source) {
    var cache = {};

    return function () {
        var key = [].join.call(arguments, '__');

        if (!(key in cache)) {
            cache[key] = source.apply(source, arguments);
        }

        return cache[key];
    };
}

function resolvePathSync(rootPath, resolveSymlinks) {
    // Turns out fs.realpathSync always defaults empty strings to cwd().
    rootPath = rootPath || process.cwd();

    // Intentionally using the sync method because this only runs when the
    // middleware is initialized, and we want it to throw if there's an error.
    if (resolveSymlinks !== false) {
        rootPath = fs.realpathSync(rootPath);
    } else {
        fs.statSync(rootPath);
    }

    // The resulting rootPath should always have a trailing slash.
    return path.normalize(rootPath + path.sep);
}
