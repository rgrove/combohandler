/*global describe, before, after, it, sinon */
var path = require('path');
var defaults = require('../lib/defaults');

describe("defaults", function () {
    /*jshint expr:true */

    var DEFAULT_PORT = parseInt(process.env.npm_package_config_port, 10) || 8000;
    var DEFAULT_SERVER = path.resolve(process.env.npm_package_config_server ||
            path.resolve(__dirname,"../lib/server"));

    describe("for worker", function () {
        it("should include port", function () {
            defaults.worker.should.have.property('port');
            defaults.worker.port.should.equal(DEFAULT_PORT);
        });

        it("should include server", function () {
            defaults.worker.should.have.property('server');
            defaults.worker.server.should.equal(DEFAULT_SERVER);
        });
    });

    describe("for master", function () {
        it("should include port and server identical to worker defaults", function () {
            defaults.master.should.have.property('port');
            defaults.master.port.should.equal(defaults.worker.port);

            defaults.master.should.have.property('server');
            defaults.master.server.should.equal(defaults.worker.server);
        });

        it("should include pids", function () {
            defaults.master.should.have.property('pids');
            defaults.master.pids.should.equal(defaults.defaultPidsDir());
        });

        it("should include timeout", function () {
            defaults.master.should.have.property('timeout');
            defaults.master.timeout.should.equal(5000);
        });

        it("should include workers", function () {
            defaults.master.should.have.property('workers');
            defaults.master.workers.should.equal(defaults.defaultWorkers());
        });
    });

    describe("defaultPidsDir()", function () {
        var _npmConfigPrefix,
            invertedPrefix;

        before(function () {
            _npmConfigPrefix = process.env.npm_config_prefix;

            /*jshint laxbreak:true */
            // invert the conditional already tested above
            invertedPrefix = process.env.npm_config_prefix = _npmConfigPrefix
                ? ""
                : "/usr/local/share/npm";
        });

        after(function () {
            // restore modified env var
            process.env.npm_config_prefix = _npmConfigPrefix;
        });

        it("should derive path from alternate method", function () {
            var pidsDir = defaults.defaultPidsDir();
            var prefixDir = invertedPrefix || path.resolve(path.dirname(process.execPath), '..');

            pidsDir.should.equal(path.join(prefixDir, 'var/run'));
        });
    });

    describe("defaultWorkers()", function () {
        it("should not exceed MAX_WORKERS", function () {
            var workers = defaults.defaultWorkers();
            workers.should.be.within(1, defaults.MAX_WORKERS);
        });
    });

});
