/*global describe, it */
var path = require('path');

var ComboWorker = require('../lib/cluster/worker');

describe("cluster worker", function () {
    describe("instantiation", function () {
        it("should support empty options arg", function () {
            var instance = new ComboWorker();

            instance.should.have.property('options');
            instance.options.should.eql(ComboWorker.defaults);
        });

        it("should support factory-style (no new)", function () {
            /*jshint newcap: false */
            var instance = ComboWorker();

            instance.should.be.an.instanceOf(ComboWorker);
            instance.should.have.property('options');
        });

        it("should merge defaults with passed options", function () {
            var instance = new ComboWorker({
                port: 8080
            });

            instance.options.port.should.equal(8080);
            instance.options.server.should.equal(ComboWorker.defaults.server);
        });

        it("should clean merged options", function () {
            var instance = new ComboWorker({
                server: 'test/fixtures/server.js'
            });

            instance.options.port.should.equal(ComboWorker.defaults.port);
            instance.options.server.should.equal(path.resolve('test/fixtures/server.js'));
        });
    });

    describe("#start()", function () {
        it("should be chainable (return this)", function () {
            var instance = new ComboWorker();

            instance.should.equal(instance.start());
        });

        it("should call provided callback", function (done) {
            var instance = new ComboWorker();

            instance.start(done);
        });
    });

    describe("#destroy()", function () {
        it("should destroy safely when server not created", function () {
            var instance = new ComboWorker();

            instance.destroy();

            instance.should.have.property('_destroyed');
            instance._destroyed.should.equal(true);
        });

        it("should call destroy callback when server not created", function (done) {
            var instance = new ComboWorker();

            instance.destroy(done);
        });
    });

    describe("#listen()", function () {
        it("should modify instance options with optional port arg", function () {
            var instance = new ComboWorker();

            // override start() to prevent execution
            instance.start = function () {};

            instance.listen(1);
            instance.options.port.should.equal(1);
        });

        it("should call #start() with callback", function (done) {
            var instance = new ComboWorker();

            // override _listen() to signal completion
            instance._listen = done;

            instance.listen();
        });

        it("should create server", function (done) {
            var instance = new ComboWorker();

            instance.listen();

            process.nextTick(function () {
                instance.should.have.property('_server');
                instance.destroy(done);
            });
        });
    });
});
