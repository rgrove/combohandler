/**
Status utility for ComboMaster.
**/

exports = module.exports = checkStatus;

function checkStatus(prefix, pid, suffix) {
    // increment zero-based forEach index to match one-based worker.id
    if (typeof suffix === 'number') {
        suffix += 1;
    }

    var name = prefix + (suffix || ""),
        status = 'alive',
        color = '36';

    try {
        process.kill(pid, 0);
    }
    catch (err) {
        if ('ESRCH' === err.code) {
            status = 'dead';
            color = '31';
        }
        else {
            throw err;
        }
    }

    logStatus(name, pid, status, color);
}

function logStatus(name, pid, status, color) {
    console.error('%s\033[90m %d\033[0m \033[' + color + 'm%s\033[0m', name, pid, status);

    if (name === 'master' && status === 'dead') {
        process.exit(1);
    }
}
