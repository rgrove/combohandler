/*global describe, it */
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
        });

        it("should consume ad-hoc string 'shutdown' param as boolean config.shutdown", function () {
            var config = args.parse(['shutdown'], 0);

            config.should.not.have.property('restart');
            config.shutdown.should.equal(true);
            config.should.not.have.property('status');
            config.should.not.have.property('stop');
        });

        it("should consume ad-hoc string 'status' param as boolean config.status", function () {
            var config = args.parse(['status'], 0);

            config.should.not.have.property('restart');
            config.should.not.have.property('shutdown');
            config.status.should.equal(true);
            config.should.not.have.property('stop');
        });

        it("should consume ad-hoc string 'stop' param as boolean config.stop", function () {
            var config = args.parse(['stop'], 0);

            config.should.not.have.property('restart');
            config.should.not.have.property('shutdown');
            config.should.not.have.property('status');
            config.stop.should.equal(true);
        });
    });

    describe("clean()", function () {
        it("should clean options in-place", function () {
            var config = {
                server: 'foo/bar.js'
            };

            args.clean(config);

            config.server.should.equal(path.resolve('foo/bar.js'));
        });

        it("should return clean options object", function () {
            var config = { port: '1234' },
                cleaned = args.clean(config);

            cleaned.port.should.equal(1234);
            config.should.equal(cleaned);
        });
    });

    describe("resolveRoots()", function () {
        it("should resolve route paths from dirname of rootsFile", function () {
            var config = args.clean({
                rootsFile: 'test/root.json'
            });

            config.should.have.property('roots');

            // route
            config.roots.should.have.property('/css');
            config.roots.should.have.property('/js');

            // rootPath
            config.roots['/css'].should.equal(path.resolve('test/fixtures/root/css'));
            config.roots['/js' ].should.equal(path.resolve('test/fixtures/root/js' ));
        });

        it("should just ignore rootsFile when it is a directory", function () {
            var config = args.clean({ rootsFile: __dirname });

            config.should.not.have.property('roots');
        });

        it("should throw error when rootsFile does not exist", function () {
            /*jshint immed:false */
            (function () {
                args.clean({ rootsFile: 'test/missing.json' });
            }).should.throwError(/^ENOENT/);
        });
    });

    describe("usage()", function () {
        it("should output string joined with newlines", function () {
            var usage = args.usage;
            usage.should.not.be.empty;
            usage.split('\n').length.should.be.above(5);
        });
    });

    describe("version()", function () {
        it("should read package.json for correct value", function () {
            var pkgVersion = require('../package.json').version;
            var gotVersion = args.version;

            gotVersion.should.equal(pkgVersion);
        });
    });
});
