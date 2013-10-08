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
    this.process.title = 'combohandler worker';

    // aid precise detaching during _destroy
    this._boundDispatch = this.dispatch.bind(this);
    this.process.on('message', this._boundDispatch);
}

util.inherits(ComboWorker, ComboBase);

ComboWorker.defaults = require('../defaults').worker;

ComboWorker.prototype.dispatch = function dispatch(msg) {
    if (!msg || !msg.hasOwnProperty('cmd')) {
        throw new Error("Message must have command");
    }
    var cmd = msg.cmd;
    if (cmd === 'listen') {
        if (msg.data) {
            this.init(msg.data);
        }
        this.listen();
    } else {
        throw new Error("Message command invalid");
    }
};

ComboWorker.prototype._destroy = function (cb) {
    this.process.removeListener('message', this._boundDispatch);

    if (this._server) {
        this._server.close(cb);
    } else {
        this._maybeCallback(cb);
    }
};

ComboWorker.prototype._listen = function () {
    var app = require(this.options.server)(this.options);
    this._server = app.listen(this.options.port);
    this._server.once('listening', this._listening.bind(this));
};

ComboWorker.prototype._listening = function () {
    this.emit('listening');
};

if (cluster.isWorker) {
    /*jshint newcap: false */
    ComboWorker();
}
