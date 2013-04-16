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

});
