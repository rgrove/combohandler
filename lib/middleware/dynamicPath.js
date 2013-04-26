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
    // don't explode when misconfigured, just pass through with a warning
    if (!options || !options.rootPath) {
        console.warn("dynamicPathMiddleware: config missing!");
        return function disabledMiddleware(req, res, next) {
            next();
        };
    }

    // private fs.stat cache
    var STAT_CACHE = {};

    var rootPath   = options.rootPath,
        dynamicKey = getDynamicKey(rootPath),
        dynamicParam,
        rootSuffix;

    // str.match() in route config returns null if no matches or [":foo"]
    if (dynamicKey) {
        // key for the req.params must be stripped of the colon
        dynamicParam = dynamicKey.substr(1);

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
            getDynamicRoot(req.params, {
                "rootPath"    : rootPath,
                "dynamicParam": dynamicParam,
                "rootSuffix"  : rootSuffix,
                "statCache"   : STAT_CACHE
            }, function (err, resolvedRootPath) {
                if (err) {
                    next(new BadRequest('Unable to resolve path: ' + req.path));
                } else {
                    res.locals.rootPath = resolvedRootPath;
                    next();
                }
            });
        } else {
            next();
        }
    };
};

function getDynamicRoot(params, opts, cb) {
    var rootPath = opts.rootPath;
    var dynamicParam = opts.dynamicParam;
    var rootSuffix = opts.rootSuffix;
    var statCache = opts.statCache;

    var dynamicValue = dynamicParam && params[dynamicParam];
    var dynamicRoot;

    // a dynamic parameter has been configured
    if (dynamicValue) {
        // rootSuffix contributes to cache key
        if (rootSuffix) {
            dynamicValue = path.join(dynamicValue, rootSuffix);
        }

        dynamicRoot = path.normalize(path.join(rootPath, dynamicValue));

        if (statCache[dynamicRoot]) {
            // a path has already been resolved
            cb(null, dynamicRoot);
        }
        else {
            // a path needs resolving
            fs.stat(dynamicRoot, function (err, stat) {
                if (err) {
                    cb(err);
                } else {
                    // cache for later short-circuit
                    statCache[dynamicRoot] = stat;
                    cb(null, dynamicRoot);
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
