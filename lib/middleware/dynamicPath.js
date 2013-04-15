/**
Middleware that provides comprehension of route parameters
("/:version/combo") to the default `combine` middleware.
**/
var fs   = require('fs');
var path = require('path');

var BadRequest = require('../error/bad-request');

/**
Route middleware to provide parsing of route parameters
into filesystem root paths.

@method dynamicPath
@param {Object} options
@return {Function}
**/
exports = module.exports = function (options) {
    options = options || {};

    var rootPath   = options.rootPath,
        dynamicKey = getDynamicKey(rootPath),
        dynamicParameter,
        rootSuffix = '';

    // str.match() in route config returns null if no matches or [":foo"]
    if (dynamicKey) {
        // key for the req.params must be stripped of the colon
        dynamicParameter = dynamicKey.substr(1);

        // if the parameter is not the last token in the rootPath
        // (e.g., '/foo/:version/bar/')
        if (path.basename(rootPath).indexOf(dynamicKey) === -1) {
            // rootSuffix must be stored for use in getDynamicRoot
            rootSuffix = rootPath.substr(rootPath.indexOf(dynamicKey) + dynamicKey.length);
        }

        // remove key + suffix from rootPath used in initial realpathSync
        rootPath = rootPath.substring(0, rootPath.indexOf(dynamicKey));
    }

    // Intentionally using the sync method because this only runs when the
    // middleware is initialized, and we want it to throw if there's an error.
    rootPath = fs.realpathSync(rootPath);

    return function dynamicPathMiddleware(req, res, next) {
        // on the off chance this middleware runs twice
        if (!res.locals.rootPath) {
            // supply subsequent middleware with the res.locals.rootPath property
            getDynamicRoot(req.params, rootPath, dynamicParameter, rootSuffix, function (err, resolved) {
                if (err) {
                    next(new BadRequest('Unable to resolve path: ' + req.path));
                } else {
                    res.locals.rootPath = resolved;
                    next();
                }
            });
        } else {
            next();
        }
    };
};

// cache for "compiled" dynamic roots
var DYNAMIC_ROOTS = exports.DYNAMIC_ROOTS = {};

function getDynamicRoot(params, rootPath, dynamicParameter, rootSuffix, cb) {
    var dynamicValue = dynamicParameter && params[dynamicParameter];

    // a dynamic parameter has been configured
    if (dynamicValue) {
        // rootSuffix contributes to cache key
        if (rootSuffix) {
            dynamicValue = path.join(dynamicValue, rootSuffix);
        }

        if (DYNAMIC_ROOTS[dynamicValue]) {
            // a path has already been resolved
            cb(null, DYNAMIC_ROOTS[dynamicValue]);
        }
        else {
            // a path needs resolving
            fs.realpath(path.normalize(path.join(rootPath, dynamicValue)), function (err, resolved) {
                if (err) {
                    cb(err);
                } else {
                    // cache for later short-circuit
                    DYNAMIC_ROOTS[dynamicValue] = resolved;
                    cb(null, resolved);
                }
            });
        }
    }
    // default to rootPath when no dynamic parameter present
    else {
        cb(null, rootPath);
    }
}

function getDynamicKey(rootPath) {
    // route parameter matches ":foo" of "/:foo/bar/"
    var paramRegex = /:\w+/;
    return paramRegex.test(rootPath) && rootPath.match(paramRegex)[0];
}
