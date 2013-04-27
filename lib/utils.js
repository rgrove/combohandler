/**
Shared Utilities
**/

exports.mix = mix;
exports.merge = merge;
exports.memoize = memoize;

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
