/**
CLI arguments and config cleaning.
**/
var nopt = require('nopt');
var path = require('path');

var knownOpts = {
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

        return config;
    }
};
