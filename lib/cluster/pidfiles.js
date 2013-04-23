/**
Manage combohandler process master and worker pidfiles

@see https://github.com/LearnBoost/cluster/blob/master/lib/plugins/pidfiles.js
**/
var fs = require('fs');
var path = require('path');
var mkdirp = require('mkdirp');

// Public API
exports.getMasterPid = getMasterPid;
exports.getWorkerPidsSync = getWorkerPidsSync;
exports.removePidFile = removePidFile;
exports.removePidFileSync = removePidFileSync;
exports.removeWorkerPidFiles = removeWorkerPidFiles;
exports.writePidFile = writePidFile;

function getPidFilePath(dir, name) {
    return path.join(dir, (name || 'master') + '.pid');
}

function getMasterPid(dir, cb) {
    fs.readFile(getPidFilePath(dir, 'master'), function (err, pid) {
        if (err) {
            return cb(err);
        }
        cb(null, parseInt(pid, 10), dir);
    });
}

function getWorkerPidFilesSync(dir) {
    return fs.readdirSync(dir).filter(function (file) {
        return file.match(/^worker.*\.pid$/);
    });
}

function getWorkerPidsSync(dir) {
    return getWorkerPidFilesSync(dir).map(function (file) {
        return parseInt(fs.readFileSync(path.join(dir, file)), 10);
    });
}

function writePidFile(dir, name, pid) {
    // ensure pids dir exists before writing the pidfile
    if (name === 'master' && !fs.existsSync(dir)) {
        mkdirp.sync(dir);
    }

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
                console.error('Could not find pidfile: %s', name);
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
