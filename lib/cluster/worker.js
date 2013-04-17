/**
ComboHandler.Cluster.Worker
**/
var cluster = require('cluster');
var util = require('util');

var ComboBase = require('./base');

exports = module.exports = ComboWorker;

/**
A factory for combohandler worker processes.

@class ComboWorker
@extends ComboBase
@constructor
@param {Object} options
**/
function ComboWorker(options) {
    // factory constructor
    if (!(this instanceof ComboWorker)) {
        return new ComboWorker(options);
    }

    ComboBase.call(this, options);

    // this doesn't work in OS X (node-v0.8.x), but whatever
    process.title = 'combohandler worker';
}

util.inherits(ComboWorker, ComboBase);

ComboWorker.defaults = require('../defaults').worker;

ComboWorker.prototype._destroy = function (cb) {
    if (this._server) {
        this._server.close(cb);
    } else {
        this._maybeCallback(cb);
    }
};

ComboWorker.prototype._listen = function () {
    var app = require(this.options.server)(this.options);
    this._server = app.listen(this.options.port);
};

if (cluster.isWorker) {
    /*jshint newcap: false */
    ComboWorker(require('../args').parse()).listen();
}
