/*global describe, it, sinon */
var path = require('path');

var ComboBase = require('../lib/cluster/base');

describe("cluster base", function () {
    /*jshint expr:true */

    describe("instantiation", function () {
        it("should support empty options arg", function () {
            var instance = new ComboBase();

            instance.should.have.property('options');
            instance.options.should.eql({});
        });

        it("should merge passed options into instance.options", function () {
            var instance = new ComboBase({
                port: 8080
            });

            instance.options.port.should.equal(8080);
        });

        it("should clean merged options", function () {
            var instance = new ComboBase({
                server: 'test/fixtures/server.js'
            });

            instance.options.server.should.equal(path.resolve('test/fixtures/server.js'));
        });
    });

    describe("#start()", function () {
        it("should be chainable (return this)", function () {
            var instance = new ComboBase();

            instance.should.equal(instance.start());
        });

        it("should pass callback to 'start' event", function (done) {
            var instance = new ComboBase();

            instance.on('start', done);

            instance.start();
        });

        it("should call provided callback", function (done) {
            var instance = new ComboBase();

            instance.start(done);
        });
    });

    describe("#destroy()", function () {
        it("should set _destroyed property", function () {
            var instance = new ComboBase();

            instance.destroy();

            instance.should.have.property('_destroyed');
            instance._destroyed.should.equal(true);
        });

        it("should call destroy callback directly when no listener for 'destroy' event", function (done) {
            var instance = new ComboBase();

            instance.destroy(done);
        });
    });

    describe("#listen()", function () {
        it("should modify instance options with optional port arg", function () {
            var instance = new ComboBase();

            // override start() to prevent execution
            instance.start = function () {};

            instance.listen(1);
            instance.options.port.should.equal(1);
        });

        it("should emit 'listen' from #start() callback", function (done) {
            var instance = new ComboBase();

            instance.on('listen', done);

            instance.listen();
        });
    });

});
