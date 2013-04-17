/**
ComboHandler.Cluster.Master
**/
var cluster = require('cluster');
var util = require('util');
var fs = require('fs');
var path = require('path');

var ComboBase = require('./base');
var checkStatus = require('./status');

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
    this._detachEvents();

    this._maybeCallback(cb);
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
    var dir = this.options.pids;

    // ensure pids dir exists before writing the pidfile
    if (!fs.existsSync(dir)) {
        require('mkdirp').sync(dir);
    }

    writePidFile(dir, 'master', process.pid);
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
    // TODO: configurable
    var startupTimeout = [],
        closingTimeout = [],
        flameouts = 0,
        timeout = this.options.timeout,
        pids = this.options.pids;

    cluster.on('fork', function (worker) {
        startupTimeout[worker.id] = setTimeout(function () {
            console.error('Something is wrong with worker %d', worker.id);
        }, timeout);
    });

    cluster.on('listening', function (worker) {
        console.error('Worker %d listening with pid %d', worker.id, worker.process.pid);
        clearTimeout(startupTimeout[worker.id]);

        // this doesn't work in OS X, but whatever
        worker.process.title = 'combohandler worker';
        writePidFile(pids, 'worker' + worker.id, worker.process.pid);
    });

    cluster.on('disconnect', function (worker) {
        console.error('Worker %d disconnecting...', worker.id);
        closingTimeout[worker.id] = setTimeout(function () {
            worker.destroy();
            console.error('Forcibly destroyed worker %d', worker.id);
        }, timeout);
    });

    cluster.on('exit', function (worker, code, signal) {
        clearTimeout(startupTimeout[worker.id]);
        clearTimeout(closingTimeout[worker.id]);

        if (worker.suicide) {
            console.error('Worker %d exited cleanly.', worker.id);
            removePidFile(pids, 'worker' + worker.id);
        }
        else {
            if (signal) {
                console.error('Worker %d received signal %s', worker.id, signal);
                if (signal === 'SIGUSR2') {
                    console.error('Worker %d restarting, removing old pidfile', worker.id);
                    removePidFile(pids, 'worker' + worker.id);
                }
            }

            if (code) {
                console.error('Worker %d exited with code %d', worker.id, code);
                if (++flameouts > 20) {
                    console.error("Too many errors during startup, bailing!");
                    removePidFileSync(pids, 'master');
                    process.exit(1);
                }
            }

            console.error('Worker %d died, respawning!', worker.id);
            cluster.fork();
        }
    });
};

// SIGINT   (Ctrl+C)
// SIGTERM  (default signal from `kill`)
ComboCluster.prototype.gracefulShutdown = function () {
    console.log('combohandler master %d shutting down...', process.pid);
    var dir = this.options.pids;
    cluster.disconnect(function () {
        process.on('exit', function () {
            removePidFileSync(dir, 'master');
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
    var dir = this.options.pids;
    getMasterPid(dir, function (err, masterPid) {
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
                    removePidFileSync(dir, 'master');
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
    var dir = this.options.pids;
    getMasterPid(dir, function (err, masterPid) {
        if (err) {
            if ('ENOENT' === err.code) {
                console.error('combohandler master not running!');
                process.exit(1);
            }
            else {
                throw err;
            }
        }

        getWorkerPidsSync(dir).forEach(checkStatus.bind({}, 'worker'));

        // check master last so we can exit non-zero when dead
        checkStatus('master', masterPid, '');
    });
};

ComboCluster.prototype.shutdown = function () {
    this._signalMaster('SIGTERM');
};

ComboCluster.prototype.stop = function () {
    // must clean up worker pidfiles before sending SIGKILL,
    // because SIGKILL listeners basically can't do anything
    removeWorkerPidFiles(this.options.pids, this._stop.bind(this));
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

// Utilities ----------------------------------------------------------------

// Manage combohandler process master and worker pidfiles
// https://github.com/LearnBoost/cluster/blob/master/lib/plugins/pidfiles.js
function getPidFilePath(dir, name) {
    return path.join(dir, (name || 'master') + '.pid');
}

function getMasterPid(dir, cb) {
    fs.readFile(getPidFilePath(dir, 'master'), function (err, pid) {
        if (pid) {
            pid = parseInt(pid, 10);
        }
        if (cb) {
            cb(err, pid);
        }
    });
}

function getWorkerPidFilesSync(dir) {
    return fs.readdirSync(dir).filter(function (file) {
        return file.match(/^worker.*\.pid$/);
    });
}

function getWorkerPidsSync(dir) {
    return getWorkerPidFilesSync(dir).map(function (file) {
        return parseInt(fs.readFileSync(dir + '/' + file), 10);
    });
}

function writePidFile(dir, name, pid) {
    fs.writeFile(getPidFilePath(dir, name), pid.toString(), function (err) {
        if (err) { throw err; }
    });
}

function removePidFile(dir, name, cb) {
    fs.unlink(getPidFilePath(dir, name), function (err) {
        if (cb) {
            cb(err);
        }
        else if (err) {
            if ('ENOENT' === err.code) {
                console.error('Could not find pidfile: %s', err.msg);
            }
            else {
                throw err;
            }
        }
    });
}

function removePidFileSync(dir, name) {
    fs.unlinkSync(getPidFilePath(dir, name));
}

function removeWorkerPidFiles(dir, cb) {
    var workerPidFiles = getWorkerPidFilesSync(dir),
        remaining = workerPidFiles.length;

    if (!remaining && cb) {
        cb();
    }

    workerPidFiles.forEach(function (file) {
        removePidFile(dir, file.replace(/\.pid$/, ''), function (err) {
            if (err) {
                if ('ENOENT' === err.code) {
                    console.error('Could not find worker pidfile: %s', file);
                }
                else {
                    throw err;
                }
            }
            if (--remaining === 0 && cb) {
                cb();
            }
        });
    });
}

