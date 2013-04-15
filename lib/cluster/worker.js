/**
ComboHandler.Cluster.Worker

@author Daniel Stockman <daniel.stockman@gmail.com>
**/
var cluster = require('cluster');

var args = require('../args');
var merge = require('../utils').merge;

exports = module.exports = ComboWorker;

/**
A factory for combohandler worker processes.

@class ComboWorker
@constructor
@param {Object} options
**/
function ComboWorker(options) {
    // factory constructor
    if (!(this instanceof ComboWorker)) {
        return new ComboWorker(options);
    }

    this.options = merge(ComboWorker.defaults, options);

    this.listen();
}

ComboWorker.defaults = args.workerDefaults;

ComboWorker.prototype.start = function (cb) {
    // this doesn't work in OS X (node-v0.8.x), but whatever
    process.title = 'combohandler worker';

    if (cb) {
        process.nextTick(cb);
    }

    // chainable
    return this;
};

ComboWorker.prototype.listen = function (port) {
    if (port) {
        this.options.port = port;
    }

    return this.start(this._listen.bind(this));
};

ComboWorker.prototype._listen = function () {
    var server = this.options.server;
    if (server) {
        require(server)(this.options).listen(this.options.port);
    }
};

if (cluster.isWorker) {
    /*jshint newcap: false */
    ComboWorker(args.parse());
}
