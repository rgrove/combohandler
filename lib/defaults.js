/**
Default values for config properties.
**/
var path = require('path');

var DEFAULT_PORT = parseInt(process.env.npm_package_config_port || 8000, 10);
var DEFAULT_SERVER = path.resolve(process.env.npm_package_config_server || __dirname + "/server");

// Cap workers to 8 maximum, unless overridden by CLI option,
// which avoids spawning too many processes on beefy boxen.
var MAX_WORKERS = exports.MAX_WORKERS = 8;

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

exports.defaultWorkers = function defaultWorkers() {
    return Math.min(require('os').cpus().length, MAX_WORKERS);
};

exports.worker = {
    "port"  : DEFAULT_PORT,
    "server": DEFAULT_SERVER
};

exports.master = {
    "pids"      : exports.defaultPidsDir(),
    "port"      : DEFAULT_PORT,
    "server"    : DEFAULT_SERVER,
    "timeout"   : 5000,
    "workers"   : exports.defaultWorkers()
};
