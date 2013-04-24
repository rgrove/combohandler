/**
ComboHandler.Cluster.Master
**/
var cluster = require('cluster');
var util = require('util');

var ComboBase = require('./base');
var checkStatus = require('./status');
var pidfiles = require('./pidfiles');

exports = module.exports = ComboCluster;

/**
A factory for running combohandler in multiple processes.

@class ComboCluster
@extends ComboBase
@constructor
@param {Object} [options]
@param {Function} [cb]
**/
function ComboCluster(options, cb) {
    if ("function" === typeof options) {
        cb = options;
        options = {};
    }

    // factory constructor
    if (!(this instanceof ComboCluster)) {
        return new ComboCluster(options);
    }

    ComboBase.call(this, options);

    // this doesn't work in OS X (node-v0.8.x), but whatever
    process.title = 'combohandler master';

    this.startupTimeout = [];
    this.closingTimeout = [];
    this.flameouts = 0;
    // TODO: configurable

    this._maybeCallback(cb);
}

util.inherits(ComboCluster, ComboBase);

ComboCluster.defaults = require('../defaults').master;

ComboCluster.prototype._start = function (cb) {
    this.setupMaster({
        exec: __dirname + '/worker.js'
    });

    this._setupMasterPidFile();
    this._attachEvents();

    this._maybeCallback(cb);
};

ComboCluster.prototype._destroy = function (cb) {
    cluster.disconnect(function () {
        this._detachEvents();
        this._maybeCallback(cb);
    }.bind(this));
};

ComboCluster.prototype.setupMaster = function (options) {
    cluster.setupMaster(options);
};

/**
Attach listeners to cluster lifecycle events.

@method _attachEvents
@private
**/
ComboCluster.prototype._attachEvents = function () {
    this._bindProcess();
    this._bindCluster();
};

/**
Detach listeners from cluster lifecycle events.

@method _detachEvents
@private
**/
ComboCluster.prototype._detachEvents = function () {
    process.removeAllListeners('SIGINT');
    process.removeAllListeners('SIGTERM');
    process.removeAllListeners('SIGUSR2');
    cluster.removeAllListeners();
};

ComboCluster.prototype._setupMasterPidFile = function () {
    pidfiles.writePidFile(this.options.pids, 'master', process.pid);
};

ComboCluster.prototype._bindProcess = function () {
    // bind shutdown helper to access this.options.pids
    var boundGracefulShutdown = this.gracefulShutdown.bind(this);

    // Signal Event Handlers
    // http://nodejs.org/api/process.html#process_signal_events
    // http://en.wikipedia.org/wiki/Unix_signal#List_of_signals
    process.on('SIGINT',  boundGracefulShutdown);
    process.on('SIGTERM', boundGracefulShutdown);
    process.on('SIGUSR2', this.restartWorkers);
};

ComboCluster.prototype._bindCluster = function () {
    cluster.on('fork',       this._workerForked.bind(this));
    cluster.on('online',     this._workerOnline.bind(this));
    cluster.on('listening',  this._workerListening.bind(this));
    cluster.on('disconnect', this._workerDisconnected.bind(this));
    cluster.on('exit',       this._workerExited.bind(this));
};

ComboCluster.prototype._workerForked = function (worker) {
    this.startupTimeout[worker.id] = setTimeout(function () {
        console.error('Something is wrong with worker %d', worker.id);
    }, this.options.timeout);
};

ComboCluster.prototype._workerOnline = function (worker) {
    console.error('Worker %d online', worker.id);
    clearTimeout(this.startupTimeout[worker.id]);

    worker.send({ cmd: 'listen', data: this.options });
};

ComboCluster.prototype._workerListening = function (worker) {
    console.error('Worker %d listening with pid %d', worker.id, worker.process.pid);
    clearTimeout(this.startupTimeout[worker.id]);

    // this doesn't work in OS X, but whatever
    worker.process.title = 'combohandler worker';
    pidfiles.writePidFile(this.options.pids, 'worker' + worker.id, worker.process.pid);
};

ComboCluster.prototype._workerDisconnected = function (worker) {
    console.error('Worker %d disconnecting...', worker.id);
    this.closingTimeout[worker.id] = setTimeout(function () {
        worker.destroy();
        console.error('Forcibly destroyed worker %d', worker.id);
    }, this.options.timeout);
};

ComboCluster.prototype._workerExited = function (worker, code, signal) {
    clearTimeout(this.startupTimeout[worker.id]);
    clearTimeout(this.closingTimeout[worker.id]);

    if (worker.suicide) {
        console.error('Worker %d exited cleanly.', worker.id);
        pidfiles.removePidFileSync(this.options.pids, 'worker' + worker.id);
    }
    else {
        if (signal) {
            console.error('Worker %d received signal %s', worker.id, signal);
            if (signal === 'SIGUSR2') {
                console.error('Worker %d restarting, removing old pidfile', worker.id);
                pidfiles.removePidFileSync(this.options.pids, 'worker' + worker.id);
            }
        }

        if (code) {
            console.error('Worker %d exited with code %d', worker.id, code);
            if (++this.flameouts > 20) {
                console.error("Too many errors during startup, bailing!");
                pidfiles.removePidFileSync(this.options.pids, 'master');
                process.exit(1);
            }
        }

        console.error('Worker %d died, respawning!', worker.id);
        cluster.fork();
    }
};

// SIGINT   (Ctrl+C)
// SIGTERM  (default signal from `kill`)
ComboCluster.prototype.gracefulShutdown = function () {
    console.log('combohandler master %d shutting down...', process.pid);
    var dir = this.options.pids;
    cluster.disconnect(function () {
        process.on('exit', function () {
            pidfiles.removePidFileSync(dir, 'master');
            console.log('combohandler master %d finished shutting down!', process.pid);
        });
    });
};

// SIGUSR2
ComboCluster.prototype.restartWorkers = function () {
    console.log('combohandler master %d restarting workers...', process.pid);
    for (var id in cluster.workers) {
        if (cluster.workers.hasOwnProperty(id)) {
            process.kill(cluster.workers[id].process.pid, 'SIGUSR2');
        }
    }
};

ComboCluster.prototype._signalMaster = function (signal) {
    pidfiles.getMasterPid(this.options.pids, function (err, masterPid, dir) {
        if (err) {
            console.error("Error sending signal %s to combohandler master process", signal);
            if ('ENOENT' === err.code) {
                console.error('combohandler master not running!');
                process.exit(1);
            }
            else {
                throw err;
            }
        } else {
            try {
                // again, because SIGKILL is so incredibly rude,
                // he doesn't allow us to do anything afterward
                if ('SIGKILL' === signal) {
                    pidfiles.removePidFileSync(dir, 'master');
                }
                // send signal to master process, not necessarily "killing" it
                process.kill(masterPid, signal);
            }
            catch (ex) {
                if ('ESRCH' === ex.code) {
                    console.error('combohandler master not running!');
                }
                else {
                    throw ex;
                }
            }
        }
    });
};

ComboCluster.prototype.restart = function () {
    this._signalMaster('SIGUSR2');
};

ComboCluster.prototype.status = function () {
    pidfiles.getMasterPid(this.options.pids, function (err, masterPid, dir) {
        if (err) {
            if ('ENOENT' === err.code) {
                console.error('combohandler master not running!');
                process.exit(1);
            }
            else {
                throw err;
            }
        }

        pidfiles.getWorkerPidsSync(dir).forEach(checkStatus.bind(null, 'worker'));

        // check master last so we can exit non-zero when dead
        checkStatus('master', masterPid, '');
    });
};

ComboCluster.prototype.shutdown = function () {
    this._signalMaster('SIGTERM');
};

ComboCluster.prototype.stop = function () {
    // must clean up worker pid files before sending SIGKILL,
    // because SIGKILL listeners basically can't do anything
    pidfiles.removeWorkerPidFiles(this.options.pids, this._stop.bind(this));
};

ComboCluster.prototype._stop = function () {
    console.error('combohandler master %d stopping abruptly...', process.pid);
    this._signalMaster('SIGKILL');
};

// _collaborate

ComboCluster.prototype._listen = function () {
    // fork
    console.log('Forking workers from combohandler master %d', process.pid);
    // console.log(this.options);
    var workers = this.options.workers;
    while (workers--) {
        cluster.fork();
    }
};
