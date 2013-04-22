/**
CLI arguments and config cleaning.
**/
var nopt = require('nopt');
var path = require('path');
var fs = require('fs');

var knownOpts = {
    "version": Boolean,
    "basePath": path,
    "cluster": Boolean,
    "maxAge": Number,
    "pids": path,
    "port": Number,
    "restart": Boolean,
    "rootsFile": path,
    "server": path,
    "shutdown": Boolean,
    "status": Boolean,
    "stop": Boolean,
    "timeout": Number,
    "workers": Number
};

var shortHands = {
    "v": ["--version"],
    "a": ["--server"],
    "b": ["--basePath"],
    "d": ["--pids"],
    "m": ["--maxAge"],
    "p": ["--port"],
    "f": ["--rootsFile"],
    "r": ["--restart"],
    "g": ["--shutdown"],
    "s": ["--status"],
    "S": ["--stop"],
    "t": ["--timeout"],
    "n": ["--workers"]
};

exports = module.exports = {
    get version() {
        return require('../package.json').version;
    },
    clean: function (config) {
        nopt.clean(config, knownOpts);

        return resolveRoots(config);
    },
    parse: function (args, slice) {
        var config = nopt(knownOpts, shortHands, args, slice);

        // allow one string argument to stand in for Boolean flag
        config.argv.remain.some(function (arg) {
            /*jshint boss: true */
            switch (arg) {
            case 'restart':
                return config.restart = true;
            case 'shutdown':
                return config.shutdown = true;
            case 'status':
                return config.status = true;
            case 'stop':
                return config.stop = true;
            }
        });

        return resolveRoots(config);
    }
};

function resolveRoots(config) {
    // parse roots json config
    if (config.rootsFile) {
        var rootStat = fs.statSync(config.rootsFile);
        if (rootStat.isFile()) {
            config.roots = require(config.rootsFile);
            var rootDir = path.dirname(config.rootsFile);

            // resolve rootDir to route paths
            Object.keys(config.roots).forEach(function (route) {
                config.roots[route] = path.resolve(rootDir, config.roots[route]);
            });
        }
    }

    return config;
}
