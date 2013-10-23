/**
Middleware that provides comprehension of route parameters
("/:version/combo") to the default `combine` middleware.
**/
var fs   = require('fs');
var path = require('path');

var BadRequest = require('../error/bad-request');
var resolvePathSync = require('../utils').resolvePathSync;

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

    function dynamicPathMiddleware(req, res, next) {
        // on the off chance this middleware runs twice
        if (!res.locals.rootPath) {
            // supply subsequent middleware with the res.locals.rootPath property
            getDynamicRoot(req.params, dynamicPathMiddleware.CONFIG, function (err, resolvedRootPath) {
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
    }

    // cache config object used in middleware
    dynamicPathMiddleware.CONFIG = parseConfig(options.rootPath, options.resolveSymlinks);

    return dynamicPathMiddleware;
};

function getDynamicRoot(params, opts, cb) {
    var rootPath = opts.rootPath;
    var dynamicParams = opts.dynamicParams;
    var rootSuffixes = opts.rootSuffixes;
    var statCache = opts.statCache;
    var dynamicRoot;

    dynamicParams.forEach(function (dynamicParam, idx) {
        var dynamicValue = dynamicParam && params[dynamicParam];
        if (dynamicValue) {
            // rootSuffixes contribute to cache key
            if (rootSuffixes[idx]) {
                dynamicValue = path.join(dynamicValue, rootSuffixes[idx]);
            }

            dynamicRoot = path.normalize(path.join(dynamicRoot || rootPath, dynamicValue));
        }
    });

    // one or more dynamic parameters have been configured
    if (dynamicRoot) {
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

function getDynamicKeys(rootPath) {
    // route parameter matches ":foo" of "/:foo/bar/"
    // as well as ":baz" and ":qux" of "/:baz/:qux/"
    return rootPath.match(/:\w+/g);
}

/**
Create a config object for use in dynamicPathMiddleware.

@method parseConfig
@param {String} rootPath
@param {Boolean} resolveSymlinks
@return {Object} config
    @property {String} config.rootPath
    @property {String} config.dynamicParam
    @property {String} config.rootSuffixes
    @property {String} config.statCache
@private
**/
function parseConfig(rootPath, resolveSymlinks) {
    rootPath = path.normalize(rootPath);

    var dynamicKeys = getDynamicKeys(rootPath);
    var dynamicParams = [];
    var rootSuffixes = [];

    // str.match() in route config returns null if no matches or [":foo"]
    if (dynamicKeys) {
        dynamicKeys.reverse().forEach(function (dynamicKey) {
            // key for the req.params must be stripped of the colon
            var keyName = dynamicKey.substr(1);

            // since we're iterating in reverse, we need to maintain
            // expected path order by always adding to the beginning
            dynamicParams.unshift(keyName);

            // if the parameter is not the last token in the rootPath
            // (e.g., '/foo/:version/bar/')
            if (path.basename(rootPath).indexOf(dynamicKey) === -1) {
                // rootSuffixes must be stored for use in getDynamicRoot
                rootSuffixes.unshift(rootPath.split(dynamicKey).pop());
            } else {
                // maintain correct indices with non-matching keys
                rootSuffixes.unshift('');
            }

            // remove key + suffix from rootPath used in initial resolvePathSync
            rootPath = rootPath.substring(0, rootPath.lastIndexOf(dynamicKey));
        });
    }

    // Intentionally using the sync method because this only runs when the
    // middleware is initialized, and we want it to throw if there's an error.
    rootPath = resolvePathSync(rootPath, resolveSymlinks);

    return {
        "rootPath"      : rootPath,
        "dynamicParams" : dynamicParams,
        "rootSuffixes"  : rootSuffixes,
        "statCache"     : {}
    };
}
