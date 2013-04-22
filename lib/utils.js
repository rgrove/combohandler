/**
Shared Utilities
**/

exports.mix = mix;
exports.merge = merge;

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
