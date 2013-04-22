/**
CLI arguments and config cleaning.
**/
var nopt = require('nopt');
var path = require('path');
var fs = require('fs');

var knownOpts = {
    "help": Boolean,
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
    "h": ["--help"],
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
    /*jshint es5: true */
    get usage() {
        var msg = [];

        msg.push("Usage: combohandler [options]");
        msg.push("");
        msg.push("General Options:");
        msg.push("  -h, --help        Output this text");
        msg.push("  -v, --version     Prints combohandler's version");
        msg.push("");
        msg.push("Combine Options:");
        msg.push("  -p, --port      * Port to listen on.                                    [8000]");
        msg.push("  -a, --server    * Script that exports an Express app [combohandler/lib/server]");
        msg.push("  -f, --rootsFile   Path to JSON routes config.");
        msg.push("  -b, --basePath    Path to prepend when rewriting relative url()s.         ['']");
        msg.push("  -m, --maxAge      Cache header value, in seconds.                   [31536000]");
        msg.push("");
        msg.push("Cluster Options:");
        msg.push("  --cluster         Enable clustering of server across multiple processes.");
        msg.push("  -d, --pids        Directory where pidfiles are stored.       [$PREFIX/var/run]");
        msg.push("  -n, --workers     Number of worker processes.          [os.cpus.length, max 8]");
        msg.push("  -t, --timeout     Timeout (in ms) for process startup/shutdown.         [5000]");
        msg.push("");
        msg.push("  -r, --restart     Restart a running master's worker processes.");
        msg.push("  -g, --shutdown    Shutdown gracefully, waiting for connections to close.");
        msg.push("  -s, --status      Logs status of master and workers.");
        msg.push("  -S, --stop        Stop server abruptly, not waiting for open connections.");
        msg.push("");
        msg.push("* The port and server options can also be set via npm package config settings:");
        msg.push("    npm -g config set combohandler:port 2702");
        msg.push("    npm -g config set combohandler:server /path/to/server.js");
        msg.push("");
        msg.push("combohandler@" + exports.version);

        return msg.join('\n');
    },
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
