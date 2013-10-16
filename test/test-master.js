/*global describe, before, after, beforeEach, afterEach, it, sinon */
var path = require('path');
var rimraf = require('rimraf');
var mkdirp = require('mkdirp');
var should = require('should');

var ComboBase = require('../lib/cluster/base');
var ComboMaster = require('../lib/cluster');

describe("cluster master", function () {
    /*jshint expr:true */

    var PIDS_DIR = 'test/fixtures/pids';

    after(cleanPidsDir);

    describe("instantiation", function () {
        it("should support empty options arg with correct defaults", function () {
            var instance = new ComboMaster();

            instance.should.have.property('options');
            instance.options.should.eql(ComboMaster.defaults);
        });

        it("should support factory-style (no new)", function () {
            /*jshint newcap: false */
            var instance = ComboMaster();

            instance.should.be.an.instanceOf(ComboMaster);
            instance.should.have.property('options');
        });

        it("should be an instance of ComboBase", function () {
            var instance = new ComboMaster();

            instance.should.be.an.instanceOf(ComboBase);
        });

        it("should call constructor callback if passed after config", function (done) {
            var instance = new ComboMaster({}, done);
        });

        it("should detect constructor callback if passed instead of config", function (done) {
            var instance = new ComboMaster(done);
        });

        it("should setup instance properties", function () {
            var instance = new ComboMaster();

            instance.should.have.property('startupTimeout');
            instance.should.have.property('closingTimeout');
            instance.should.have.property('flameouts');

            instance.startupTimeout.should.eql([]);
            instance.closingTimeout.should.eql([]);
            instance.flameouts.should.equal(0);
        });
    });

    describe("on 'start'", function () {
        before(cleanPidsDir);

        beforeEach(function () {
            var instance = new ComboMaster({
                pids: PIDS_DIR
            });

            sinon.stub(instance.cluster, "setupMaster");
            sinon.stub(instance.pidutil, "writePidFileSync");

            sinon.spy(instance.cluster, "on");
            sinon.spy(instance.process, "on");

            this.instance = instance;
        });

        afterEach(function () {
            var instance = this.instance;

            instance.cluster.setupMaster.restore();
            instance.pidutil.writePidFileSync.restore();

            instance.cluster.on.restore();
            instance.process.on.restore();

            instance.emit('cleanup');
            this.instance = instance = null;
        });

        after(cleanPidsDir);

        it("should setupMaster with exec config", function (done) {
            var instance = this.instance;
            var setupMaster = instance.cluster.setupMaster;
            instance.start(function () {
                setupMaster.calledOnce.should.be.ok;
                setupMaster.calledWith(sinon.match.object);
                setupMaster.firstCall.args[0]
                    .should.have.property('exec', path.resolve(__dirname, '../lib/cluster/worker.js'));

                done();
            });
        });

        it("should create master.pid", function (done) {
            var instance = this.instance;
            var writePidFileSync = instance.pidutil.writePidFileSync;
            instance.start(function () {
                writePidFileSync.calledOnce.should.be.ok;
                writePidFileSync.calledWith(instance.options.pids, 'master', instance.process.pid).should.be.ok;

                done();
            });
        });

        it("should attach cluster and process events", function (done) {
            var instance = this.instance;
            instance.start(function () {
                verifyCluster(instance.cluster.on);
                verifyProcess(instance.process.on);

                done();
            });
        });
    });

    describe("on 'destroy'", function () {
        beforeEach(function () {
            var instance = new ComboMaster();

            sinon.spy(instance.cluster, "removeListener");
            sinon.spy(instance.process, "removeListener");

            sinon.stub(instance.cluster, "disconnect").yields();
            this.instance = instance;
        });

        afterEach(function () {
            var instance = this.instance;

            instance.cluster.removeListener.restore();
            instance.process.removeListener.restore();

            instance.cluster.disconnect.restore();
            this.instance = instance = null;
        });

        it("should detach cluster and process events", function (done) {
            var instance = this.instance;

            sinon.stub(instance.cluster, "setupMaster");
            sinon.stub(instance.pidutil, "writePidFileSync");

            instance.start();

            instance.destroy(function () {
                verifyCluster(instance.cluster.removeListener);
                verifyProcess(instance.process.removeListener);

                instance.cluster.setupMaster.restore();
                instance.pidutil.writePidFileSync.restore();

                done();
            });
        });

        it("should not error when destroy callback missing", function () {
            var instance = this.instance;

            /*jshint immed:false */
            (function () {
                instance.destroy();
            }).should.not.throwError();
        });
    });

    describe("signal methods:", function () {
        beforeEach(createInstance);
        afterEach(cleanupInstance);

        describe("#status()", function () {
            describe("when master.pid missing", function () {
                it("should log ENOENT error", function () {
                    var instance = this.instance;
                    var consoleError = sinon.stub(console, "error");
                    var processExit = sinon.stub(instance.process, "exit");

                    sinon.stub(instance.pidutil, "getMasterPid").yields({ code: "ENOENT" });

                    instance.status();

                    // verify that error message was sent
                    consoleError.calledOnce.should.be.ok;
                    consoleError.calledWith('combohandler master not running!').should.be.ok;

                    processExit.calledOnce.should.be.ok;
                    processExit.firstCall.calledWith(1).should.be.ok;

                    consoleError.restore();
                    processExit.restore();
                    instance.pidutil.getMasterPid.restore();
                });

                it("should throw non-ENOENT error", function () {
                    var instance = this.instance;

                    sinon.stub(instance.pidutil, "getMasterPid").yields({ code: "FOO" });

                    /*jshint immed:false */
                    (function () {
                        instance.status();
                    }).should.throwError();

                    instance.pidutil.getMasterPid.restore();
                });
            });

            it("should log master state", function () {
                var instance = this.instance;
                var consoleError = sinon.stub(console, "error");

                sinon.stub(instance.pidutil, "getWorkerPidsSync").returns([]);

                sinon.stub(instance.pidutil, "getMasterPid")
                        .yields(null, process.pid, instance.options.pids);

                instance.status();

                consoleError.calledOnce.should.be.ok;
                consoleError.firstCall.args[0].should.equal('%s\u001b[90m %d\u001b[0m \u001b[36m%s\u001b[0m');
                consoleError.firstCall.args[1].should.equal('master');
                consoleError.firstCall.args[2].should.equal(process.pid);
                consoleError.firstCall.args[3].should.equal('alive');

                consoleError.restore();
                instance.pidutil.getWorkerPidsSync.restore();
                instance.pidutil.getMasterPid.restore();
            });
        });

        describe("#restart()", function () {
            describe("when master.pid missing", function () {
                it("should log ENOENT error", function () {
                    var instance = this.instance;
                    var consoleError = sinon.stub(console, "error");
                    var processExit = sinon.stub(instance.process, "exit");

                    sinon.stub(instance.pidutil, "getMasterPid").yields({ code: "ENOENT" });

                    instance.restart();

                    // verify that error messages were sent
                    consoleError.calledTwice.should.be.ok;
                    consoleError.calledWith("Error sending signal %s to combohandler master process", 'SIGUSR2');
                    consoleError.calledWith('combohandler master not running!').should.be.ok;

                    processExit.calledOnce.should.be.ok;
                    processExit.firstCall.calledWith(1).should.be.ok;

                    consoleError.restore();
                    processExit.restore();
                    instance.pidutil.getMasterPid.restore();
                });

                it("should throw non-ENOENT error", function () {
                    var instance = this.instance;
                    var consoleError = sinon.stub(console, "error");

                    sinon.stub(instance.pidutil, "getMasterPid").yields({ code: "FOO" });

                    /*jshint immed:false */
                    (function () {
                        instance.restart();
                    }).should.throwError();

                    // verify that error message was sent
                    consoleError.calledOnce.should.be.ok;
                    consoleError.calledWith("Error sending signal %s to combohandler master process", 'SIGUSR2');

                    consoleError.restore();
                    instance.pidutil.getMasterPid.restore();
                });
            });

            describe("when previous master did not clean pidfile", function () {
                it("should log ESRCH error", function () {
                    var instance = this.instance;
                    var consoleError = sinon.stub(console, "error");

                    sinon.stub(instance.pidutil, "getMasterPid")
                            .yields(null, process.pid, instance.options.pids);

                    sinon.stub(instance.process, "kill").throws({ code: "ESRCH" });

                    instance.restart();

                    // verify that error message was sent
                    consoleError.calledOnce.should.be.ok;
                    consoleError.calledWith('combohandler master not running!').should.be.ok;

                    consoleError.restore();
                    instance.pidutil.getMasterPid.restore();
                    instance.process.kill.restore();
                });

                it("should throw non-ESRCH error", function () {
                    var instance = this.instance;

                    sinon.stub(instance.pidutil, "getMasterPid")
                            .yields(null, process.pid, instance.options.pids);

                    sinon.stub(instance.process, "kill").throws({ code: "FOO" });

                    /*jshint immed:false */
                    (function () {
                        instance.restart();
                    }).should.throwError();

                    instance.pidutil.getMasterPid.restore();
                    instance.process.kill.restore();
                });
            });

            it("should send SIGUSR2 to master", signalMasterSuccess('restart', 'SIGUSR2'));
        });

        describe("#shutdown()", function () {
            it("should send SIGTERM to master", signalMasterSuccess('shutdown', 'SIGTERM'));
        });

        describe("#stop()", function () {
            it("should send SIGKILL to master", signalMasterSuccess('stop', 'SIGKILL'));
        });

        function signalMasterSuccess(methodName, expectedSignal) {
            return function () {
                var instance = this.instance;
                var consoleError = sinon.stub(console, "error"); // silence
                var processKill = sinon.stub(instance.process, "kill");

                sinon.stub(instance.pidutil, "getMasterPid")
                        .yields(null, process.pid, instance.options.pids);

                sinon.stub(instance.pidutil, "removePidFileSync");
                sinon.stub(instance.pidutil, "removeWorkerPidFiles").yields();

                instance[methodName]();

                // match arguments
                processKill.calledOnce.should.be.ok;
                processKill.firstCall.args[0].should.equal(process.pid);
                processKill.firstCall.args[1].should.equal(expectedSignal);

                // remove stubs
                consoleError.restore();
                processKill.restore();
                instance.pidutil.getMasterPid.restore();
                instance.pidutil.removePidFileSync.restore();
                instance.pidutil.removeWorkerPidFiles.restore();
            };
        }
    });

    describe("process event handlers:", function () {
        // stubbing console.log must be done inside tests :(
        beforeEach(createInstance);
        afterEach(cleanupInstance);

        describe("gracefulShutdown()", function () {
            it("should call cluster.disconnect", function () {
                var instance = this.instance;
                var consoleLog = sinon.stub(console, "log"); // silence

                sinon.stub(instance.cluster, "disconnect");

                instance.gracefulShutdown();

                instance.cluster.disconnect.calledOnce.should.be.ok;
                instance.cluster.disconnect.calledWith(sinon.match.func).should.be.ok;

                consoleLog.restore();
                instance.cluster.disconnect.restore();
            });

            it("should hook process 'exit'", function () {
                var instance = this.instance;
                var consoleLog = sinon.stub(console, "log"); // silence

                sinon.stub(instance.cluster, "disconnect").yields();
                sinon.stub(instance.process, "once");

                instance.gracefulShutdown();

                instance.process.once.calledOnce.should.be.ok;
                instance.process.once.calledWith('exit', sinon.match.func).should.be.ok;

                consoleLog.restore();
                instance.cluster.disconnect.restore();
                instance.process.once.restore();
            });

            it("should remove master pidfile on process exit", function () {
                var instance = this.instance;
                var consoleLog = sinon.stub(console, "log"); // verify later

                sinon.stub(instance.cluster, "disconnect").yields();
                sinon.stub(instance.pidutil, "removePidFileSync");

                var processOnce = sinon.stub(instance.process, "once");
                processOnce.withArgs("exit", sinon.match.func).callsArg(1); // where the magic happens

                instance.gracefulShutdown();

                consoleLog.calledTwice.should.be.ok;
                consoleLog.calledWith('combohandler master %d shutting down...', process.pid).should.be.ok;
                consoleLog.calledWith('combohandler master %d finished shutting down!', process.pid).should.be.ok;

                instance.pidutil.removePidFileSync.callCount.should.equal(1);
                instance.pidutil.removePidFileSync.calledWith(instance.options.pids, 'master');

                consoleLog.restore();
                instance.cluster.disconnect.restore();
                instance.pidutil.removePidFileSync.restore();
                processOnce.restore();
            });
        });

        describe("restartWorkers()", function () {
            beforeEach(function () {
                this.instance.cluster.workers = {
                    "1": { process: { pid: 1 } },
                    "2": { process: { pid: 2 } },
                    "3": { process: { pid: 3 } }
                };
            });
            afterEach(function () {
                this.instance.cluster.workers = {};
            });

            it("should send SIGUSR2 to all worker processes", function () {
                var instance = this.instance;
                var consoleLog = sinon.stub(console, "log"); // silence
                var processKill = sinon.stub(instance.process, "kill");

                instance.restartWorkers();

                processKill.callCount.should.equal(3);
                processKill.getCall(0).calledWith(1, "SIGUSR2");
                processKill.getCall(1).calledWith(2, "SIGUSR2");
                processKill.getCall(2).calledWith(3, "SIGUSR2");

                processKill.restore();
                consoleLog.restore();
            });
        });
    });

    describe("worker event", function () {
        beforeEach(createInstance);
        afterEach(cleanupInstance);

        function WorkerAPI(id) {
            this.id = id;
            this.process = {
                pid: 1e6 + id
            };
        }
        WorkerAPI.prototype.send = function () {};
        WorkerAPI.prototype.destroy = function () {};

        describe("'fork'", function () {
            it("should set startupTimeout", function () {
                var instance = this.instance;
                var worker = { id: 1 };

                instance._bindCluster();

                instance.startupTimeout.should.be.empty;
                instance.cluster.emit('fork', worker);
                instance.startupTimeout.should.have.property("1");

                clearTimeout(instance.startupTimeout["1"]);
            });

            it("should log error if startupTimeout elapsed", function () {
                var instance = this.instance;
                var worker = { id: 1 };
                var consoleError = sinon.stub(console, "error");
                var clock = sinon.useFakeTimers("setTimeout");

                instance._bindCluster();
                instance.options.timeout = 10;

                instance.cluster.emit('fork', worker);
                clock.tick(20);

                consoleError.calledOnce.should.be.ok;
                consoleError.calledWith('Something is wrong with worker %d', 1).should.be.ok;

                consoleError.restore();
                clock.restore();
            });
        });

        describe("'online'", function () {
            it("should clear startupTimeout", function () {
                var instance = this.instance;
                var worker = sinon.mock(new WorkerAPI(1));
                var consoleError = sinon.stub(console, "error"); // silence

                instance._bindCluster();
                instance.startupTimeout["1"] = setTimeout(function() {
                    should.fail();
                }, 100);

                instance.cluster.emit('online', worker.object);

                instance.startupTimeout["1"].should.have.property('ontimeout', null);
                consoleError.restore();
            });

            it("should send 'listen' command", function () {
                var instance = this.instance;
                var worker = sinon.mock(new WorkerAPI(1));
                var consoleError = sinon.stub(console, "error"); // silence

                worker.expects("send").once().withArgs({
                    cmd: 'listen',
                    data: instance.options
                });

                instance._bindCluster();

                instance.cluster.emit('fork', worker.object);
                instance.cluster.emit('online', worker.object);

                worker.verify();
                consoleError.restore();
            });
        });

        describe("'listening'", function () {
            it("should write worker pidfile", function () {
                var instance = this.instance;
                var worker = sinon.mock(new WorkerAPI(1));
                var consoleError = sinon.stub(console, "error"); // silence

                var writePidFileSync = sinon.stub(instance.pidutil, "writePidFileSync");

                instance._bindCluster();

                instance.cluster.emit('listening', worker.object);

                worker.object.process.should.have.property('title', 'combohandler worker');

                writePidFileSync.calledOnce.should.be.ok;
                writePidFileSync.calledWith(
                    instance.options.pids, 'worker1', worker.object.process.pid
                ).should.be.ok;

                consoleError.restore();
                writePidFileSync.restore();
            });
        });

        describe("'disconnect'", function () {
            it("should set closingTimeout", function () {
                var instance = this.instance;
                var worker = { id: 1 };
                var consoleError = sinon.stub(console, "error"); // silence

                instance._bindCluster();
                instance.closingTimeout.should.be.empty;

                instance.cluster.emit('disconnect', worker);

                instance.closingTimeout.should.have.property("1");
                clearTimeout(instance.startupTimeout["1"]);
                // timeouts aren't pushed onto the stack, they are assigned sparsely by id

                consoleError.restore();
            });

            it("should destroy() worker when closingTimeout expires", function (done) {
                var instance = this.instance;
                var worker = sinon.mock(new WorkerAPI(1));
                var consoleError = sinon.stub(console, "error"); // silence

                instance.options.timeout = 10;

                worker.expects("destroy").once();

                instance._bindCluster();
                instance.cluster.emit('disconnect', worker.object);

                setTimeout(function () {
                    worker.verify();
                    consoleError.restore();
                    done();
                }, 25);
            });
        });

        describe("'exit'", function () {
            beforeEach(function () {
                this.consoleError = sinon.stub(console, "error"); // silence
                sinon.stub(this.instance.cluster, "fork");
                this.instance._bindCluster();
            });
            afterEach(function () {
                this.consoleError.restore();
                this.consoleError = null;
                this.instance.cluster.fork.restore();
            });

            it("should clear startup and closing timeouts", function () {
                var instance = this.instance;

                instance.startupTimeout[1] = setTimeout(should.fail, 100);
                instance.closingTimeout[1] = setTimeout(should.fail, 100);

                instance.cluster.emit('exit', { id: 1 });

                instance.startupTimeout[1].should.have.property('ontimeout', null);
                instance.closingTimeout[1].should.have.property('ontimeout', null);
            });

            describe("suicide", function () {
                it("should not spawn new worker", function () {
                    var instance = this.instance;
                    var removePidFile = sinon.stub(instance.pidutil, "removePidFileSync");

                    instance.cluster.emit('exit', { id: 1, suicide: true });
                    instance.cluster.fork.callCount.should.equal(0);

                    removePidFile.restore();
                });

                it("should remove worker pidfile", function () {
                    var instance = this.instance;
                    var removePidFile = sinon.stub(instance.pidutil, "removePidFileSync");

                    instance.cluster.emit('exit', { id: 1, suicide: true });

                    removePidFile.callCount.should.equal(1);
                    removePidFile.calledWith(instance.options.pids, 'worker1.pid');

                    removePidFile.restore();
                });
            });

            describe("natural death", function () {
                it("should spawn new worker", function () {
                    var instance = this.instance;
                    instance.cluster.emit('exit', { id: 1 });
                    instance.cluster.fork.calledOnce.should.be.ok;
                });
            });

            describe("reloading", function () {
                it("should remove worker pidfile", function () {
                    var instance = this.instance;
                    var removePidFile = sinon.stub(instance.pidutil, "removePidFileSync");

                    instance.cluster.emit('exit', { id: 1 }, null, "SIGUSR2");

                    removePidFile.callCount.should.equal(1);
                    removePidFile.calledWith(instance.options.pids, 'worker1.pid');
                    removePidFile.restore();
                });

                it("should not remove worker pidfile when worker receives a different signal", function () {
                    var instance = this.instance;
                    var removePidFile = sinon.stub(instance.pidutil, "removePidFileSync");

                    instance.cluster.emit('exit', { id: 1 }, null, "SIGKILL");

                    removePidFile.callCount.should.equal(0);
                    removePidFile.restore();
                });
            });

            describe("flameouts", function () {
                it("should not exit when flameouts threshhold unmet", function () {
                    var instance = this.instance;
                    instance.flameouts = 0;

                    instance.cluster.emit('exit', { id: 1 }, 1);

                    this.consoleError.calledWith('Worker %d exited with code %d', 1, 1).should.be.ok;
                });

                it("should exit when flameouts threshhold exceeded", function (done) {
                    var instance = this.instance;
                    var consoleError = this.consoleError;
                    var removePidFile = sinon.stub(instance.pidutil, "removePidFileSync");

                    var processExit = sinon.stub(instance.process, "exit", function (exitCode) {
                        // verify that error messages were sent
                        consoleError.calledTwice.should.be.ok;
                        consoleError.calledWith("Too many errors during startup, bailing!");

                        removePidFile.callCount.should.equal(1);
                        removePidFile.calledWith(instance.options.pids, 'master.pid');

                        // should not spawn another worker
                        instance.cluster.fork.callCount.should.equal(0);

                        exitCode.should.equal(1);

                        removePidFile.restore();
                        processExit.restore();

                        done();
                    });

                    instance.flameouts = 20;
                    instance.cluster.emit('exit', { id: 1 }, 1);
                });
            });
        });
    });

    describe("on 'listen'", function () {
        beforeEach(createInstance);
        afterEach(cleanupInstance);

        it("should fork workers", function (done) {
            var consoleLog = sinon.stub(console, "log"); // silence

            var instance = this.instance;
            instance.options.workers = 1;

            var setupMaster = sinon.stub(instance.cluster, "setupMaster");
            var clusterFork = sinon.stub(instance.cluster, "fork");

            instance.on('listen', function () {
                setTimeout(function () {
                    clusterFork.calledOnce.should.be.ok;
                    clusterFork.restore();
                    setupMaster.restore();
                    consoleLog.restore();
                    done();
                }, 10);
            });

            instance.listen();
        });
    });

    // Test Utilities ---------------------------------------------------------

    function verifyCluster(spyCluster) {
        spyCluster.callCount.should.equal(5);

        spyCluster.getCall(0).calledWith('fork',       sinon.match.func).should.be.ok;
        spyCluster.getCall(1).calledWith('online',     sinon.match.func).should.be.ok;
        spyCluster.getCall(2).calledWith('listening',  sinon.match.func).should.be.ok;
        spyCluster.getCall(3).calledWith('disconnect', sinon.match.func).should.be.ok;
        spyCluster.getCall(4).calledWith('exit',       sinon.match.func).should.be.ok;

        return spyCluster;
    }

    function verifyProcess(spyProcess) {
        spyProcess.callCount.should.equal(3);

        spyProcess.getCall(0).calledWith('SIGINT',     sinon.match.func).should.be.ok;
        spyProcess.getCall(1).calledWith('SIGTERM',    sinon.match.func).should.be.ok;
        spyProcess.getCall(2).calledWith('SIGUSR2',    sinon.match.func).should.be.ok;

        return spyProcess;
    }

    function makePidsDir(done) {
        mkdirp(PIDS_DIR, done);
    }

    function cleanPidsDir(done) {
        rimraf(PIDS_DIR, done);
    }

    function createInstance(done) {
        this.instance = new ComboMaster({ pids: PIDS_DIR });
        makePidsDir(done);
    }

    function cleanupInstance(done) {
        this.instance.emit('cleanup');
        this.instance = null;
        cleanPidsDir(done);
    }
});
