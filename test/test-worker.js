/*global describe, it, sinon */

var ComboBase = require('../lib/cluster/base');
var ComboWorker = require('../lib/cluster/worker');

describe("cluster worker", function () {
    /*jshint expr:true */

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

        it("should bind dispatcher to process", function () {
            var instance = new ComboWorker();
            var msgListeners = instance.process.listeners('message').slice();
            var dispatcherIndex = msgListeners.indexOf(instance._boundDispatch);

            instance.should.have.property('_boundDispatch');
            instance._boundDispatch.should.be.a.Function;

            // callback should be the last in the stack
            dispatcherIndex.should.equal(msgListeners.length - 1);
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

        it("should remove 'message' listener", function (done) {
            var instance = new ComboWorker();

            instance.destroy(function () {
                var msgListeners = instance.process.listeners('message').slice();
                var dispatcherIndex = msgListeners.indexOf(instance._boundDispatch);

                dispatcherIndex.should.equal(-1);

                done();
            });
        });
    });

    describe("on 'message'", function () {
        it("should error when message missing", function (done) {
            /*jshint immed:false */
            var worker = new ComboWorker();

            (function () {
                worker.dispatch();
            }).should.throwError("Message must have command");

            worker.destroy(done);
        });

        it("should error when message command missing", function (done) {
            /*jshint immed:false */
            var worker = new ComboWorker();

            (function () {
                worker.dispatch({ data: { foo: "foo" } });
            }).should.throwError("Message must have command");

            worker.destroy(done);
        });

        it("should dispatch only matching commands", function (done) {
            /*jshint immed:false */
            var worker = new ComboWorker();

            (function () {
                worker.dispatch({ cmd: "poopypants" });
            }).should.throwError("Message command invalid");

            worker.destroy(done);
        });

        it("should dispatch 'listen' without data", function (done) {
            var worker = new ComboWorker();

            worker.listen = function () {
                worker.destroy(done);
            };

            worker.dispatch({ cmd: "listen" });
        });

        it("should dispatch 'listen' with data", function (done) {
            var worker = new ComboWorker();

            var json = {
                "cmd": "listen",
                "data": { "foo": "foo" }
            };

            worker.listen = function () {
                worker.options.should.have.property('foo');
                worker.options.foo.should.equal('foo');
                worker.destroy(done);
            };

            worker.dispatch(json);
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
