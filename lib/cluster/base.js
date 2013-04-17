/**
ComboHandler.Cluster.Base
**/
var EventEmitter = require('events').EventEmitter;

var args = require('../args');

exports = module.exports = ComboBase;

/**
A base class for combohandler cluster processes.

@class ComboBase
@extends EventEmitter
@constructor
@param {Object} options
**/
function ComboBase(options) {
    EventEmitter.call(this);

    this.init(options);

    if (this._start)   { this.on('start',   this._start);   }
    if (this._destroy) { this.on('destroy', this._destroy); }
    if (this._listen)  { this.on('listen',  this._listen);  }
}

require('util').inherits(ComboBase, EventEmitter);

ComboBase.prototype.init = function (options) {
    this.options = args.clean(merge(this.constructor.defaults, options));
};

ComboBase.prototype._maybeCallback = function (cb) {
    if (cb) {
        process.nextTick(cb);
    }
};

ComboBase.prototype.start = function (cb) {
    if (!this.emit('start', cb)) {
        this._maybeCallback(cb);
    }

    // chainable
    return this;
};

ComboBase.prototype.destroy = function (cb) {
    if (!this.emit('destroy', cb)) {
        this._maybeCallback(cb);
    }

    this._destroyed = true;
};

/**
Listen to a port.

@method listen
@param {Number} [port]
@public
**/
ComboBase.prototype.listen = function (port) {
    if (port) {
        this.options.port = port;
    }

    function cb() {
        this.emit('listen');
    }

    return this.start(cb.bind(this));
};

// -- Private Methods ---------------------------------------------------------

function mix(receiver, supplier) {
    if (supplier) {
        Object.keys(supplier).forEach(function (k) {
            receiver[k] = supplier[k];
        });
    }

    return receiver;
}

function merge() {
    var result = {};

    ([].slice.call(arguments)).forEach(function (obj) {
        mix(result, obj);
    });

    return result;
}
