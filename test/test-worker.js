/*global describe, it */

var ComboBase = require('../lib/cluster/base');
var ComboWorker = require('../lib/cluster/worker');

describe("cluster worker", function () {
    describe("instantiation", function () {
        it("should support empty options arg with correct defaults", function () {
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

        it("should be an instance of ComboBase", function () {
            var instance = new ComboWorker();

            instance.should.be.an.instanceOf(ComboBase);
        });
    });

    describe("on 'destroy'", function () {
        it("should not error when #destroy() callback missing", function () {
            var instance = new ComboWorker();

            instance.destroy();
        });

        it("should execute callback directly when server not created", function (done) {
            var instance = new ComboWorker();

            instance.destroy(done);
        });
    });

    describe("on 'listen'", function () {
        it("should create server and emit 'listening'", function (done) {
            var instance = new ComboWorker();

            instance.once('listening', function () {
                instance.should.have.property('_server');
                instance.destroy(done);
            });

            instance.listen();
        });
    });
});
