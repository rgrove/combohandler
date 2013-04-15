/**
CLI arguments and config cleaning.
**/
var nopt = require('nopt');
var path = require('path');

var merge = require('./utils').merge;

var knownOpts = {
    "basePath": path,
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
    clean: function (config) {
        nopt.clean(config, knownOpts);

        return config;
    },
    parse: function (args, slice) {
        var config = nopt(knownOpts, shortHands, args, slice);

        // allow one string argument to stand in for boolean flag
        // or basePath config values
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
            default:
                // support basePath
                return config.basePath = path.resolve(arg);
            }
        });

        return config;
    }
};

// -- Defaults ----------------------------------------------------------------

exports.defaultPidsDir = function defaultPidsDir() {
    var prefixDir;

    // support `npm start combohandler` or `node server.js &`
    if (process.env.npm_config_prefix) {
        prefixDir = process.env.npm_config_prefix;
    }
    else {
        prefixDir = path.resolve(path.dirname(process.execPath), '..');
    }

    // ex: /usr/local/var/run/
    return path.join(prefixDir, 'var/run');
};

// Cap workers to 8 maximum, unless overridden by CLI option,
// which avoids spawning too many processes on beefy boxen.
var MAX_WORKERS = exports.MAX_WORKERS = 8;

exports.defaultWorkers = function defaultWorkers() {
    return Math.min(require('os').cpus().length, MAX_WORKERS);
};

exports.workerDefaults = {
    "port"  : 3000,
    "server": __dirname + "/server"
};

exports.masterDefaults = merge(exports.workerDefaults, {
    "basePath"  : process.cwd(),
    "pids"      : exports.defaultPidsDir(),
    "timeout"   : 5000,
    "workers"   : exports.defaultWorkers()
});
