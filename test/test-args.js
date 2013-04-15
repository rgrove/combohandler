/*global describe, before, after, it */
var path = require('path');
var args = require('../lib/args');

describe("args", function () {

    describe("parse()", function () {
        it("should consume ad-hoc string 'restart' param as boolean config.restart", function () {
            var config = args.parse(['restart'], 0);

            config.restart.should.equal(true);
            config.should.not.have.property('shutdown');
            config.should.not.have.property('status');
            config.should.not.have.property('stop');
            config.should.not.have.property('basePath');
        });

        it("should consume ad-hoc string 'shutdown' param as boolean config.shutdown", function () {
            var config = args.parse(['shutdown'], 0);

            config.should.not.have.property('restart');
            config.shutdown.should.equal(true);
            config.should.not.have.property('status');
            config.should.not.have.property('stop');
            config.should.not.have.property('basePath');
        });

        it("should consume ad-hoc string 'status' param as boolean config.status", function () {
            var config = args.parse(['status'], 0);

            config.should.not.have.property('restart');
            config.should.not.have.property('shutdown');
            config.status.should.equal(true);
            config.should.not.have.property('stop');
            config.should.not.have.property('basePath');
        });

        it("should consume ad-hoc string 'stop' param as boolean config.stop", function () {
            var config = args.parse(['stop'], 0);

            config.should.not.have.property('restart');
            config.should.not.have.property('shutdown');
            config.should.not.have.property('status');
            config.stop.should.equal(true);
            config.should.not.have.property('basePath');
        });

        it("should consume any other ad-hoc string param as config.basePath", function () {
            var config = args.parse(['foo'], 0);

            config.should.not.have.property('restart');
            config.should.not.have.property('shutdown');
            config.should.not.have.property('status');
            config.should.not.have.property('stop');
            config.should.have.property('basePath');

            config.basePath.should.equal(path.resolve('foo'));
        });
    });

    describe("clean()", function () {
        it("should clean options in-place", function () {
            var config = {
                rootsFile: 'foo/bar.json'
            };

            args.clean(config);

            config.rootsFile.should.equal(path.resolve('foo/bar.json'));
        });

        it("should return clean options object", function () {
            var config1 = { port: '1234' },
                config2 = args.clean(config1);

            config2.port.should.equal(1234);
            config1.should.equal(config2);
        });
    });

    describe("workerDefaults", function () {
        it("should include port", function () {
            args.workerDefaults.should.have.property('port');
            args.workerDefaults.port.should.equal(3000);
        });

        it("should include server", function () {
            args.workerDefaults.should.have.property('server');
            args.workerDefaults.server.should.equal(path.resolve(path.join(__dirname, '../lib/server')));
        });
    });

    describe("masterDefaults", function () {
        it("should include port and server mixed from workerDefaults", function () {
            args.masterDefaults.should.have.property('port');
            args.workerDefaults.port.should.equal(args.workerDefaults.port);

            args.masterDefaults.should.have.property('server');
            args.workerDefaults.server.should.equal(args.workerDefaults.server);
        });

        it("should include pids", function () {
            args.masterDefaults.should.have.property('pids');
            args.masterDefaults.pids.should.equal(args.defaultPidsDir());
        });

        it("should include timeout", function () {
            args.masterDefaults.should.have.property('timeout');
            args.masterDefaults.timeout.should.equal(5000);
        });

        it("should include workers", function () {
            args.masterDefaults.should.have.property('workers');
            args.masterDefaults.workers.should.equal(args.defaultWorkers());
        });

        describe("defaultPidsDir()", function () {
            var _npmConfigPrefix,
                invertedPrefix;

            before(function () {
                _npmConfigPrefix = process.env.npm_config_prefix;

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
                var pidsDir = args.defaultPidsDir();
                var prefixDir = invertedPrefix || path.resolve(path.dirname(process.execPath), '..');

                pidsDir.should.equal(path.join(prefixDir, 'var/run'));
            });
        });

        describe("defaultWorkers()", function () {
            it("should not exceed MAX_WORKERS", function () {
                var workers = args.defaultWorkers();
                workers.should.be.below(args.MAX_WORKERS);
            });
        });
    });

});
