/*global describe, before, after, beforeEach, afterEach, it, sinon */
var fs = require('fs');
var path = require('path');
var rimraf = require('rimraf');
var mkdirp = require('mkdirp');

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

            sinon.spy(instance.cluster, "on");
            sinon.spy(instance.process, "on");

            this.instance = instance;
        });

        afterEach(function () {
            var instance = this.instance;

            instance.cluster.on.restore();
            instance.process.on.restore();

            instance.emit('cleanup');
            this.instance = instance = null;
        });

        after(cleanPidsDir);

        it("should setupMaster with exec config", function (done) {
            var instance = this.instance;
            instance.setupMaster = function (options) {
                options.should.have.property('exec');
                options.exec.should.equal(path.resolve(__dirname, '../lib/cluster/worker.js'));
            };
            instance.start(done);
        });

        it("should create master.pid", function (done) {
            var instance = this.instance;
            instance.start(function () {
                fs.readFile(path.join(instance.options.pids, 'master.pid'), done);
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

            sinon.stub(instance.cluster, "disconnect");
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
            instance.start();

            instance.destroy(function () {
                verifyCluster(instance.cluster.removeListener);
                verifyProcess(instance.process.removeListener);

                done();
            });

            instance.cluster.disconnect.invokeCallback();
        });

        it("should not error when destroy callback missing", function () {
            var instance = this.instance;

            /*jshint immed:false */
            (function () {
                instance.destroy();
            }).should.not.throwError();

            instance.cluster.disconnect.invokeCallback();
        });
    });

    describe("signal methods", function () {
        afterEach(cleanPidsDir);

        it("#status() should log master state", function (done) {
            this.timeout(100);

            var instance = new ComboMaster({ pids: PIDS_DIR });

            instance.emit('start', function () {
                instance._detachEvents();
                instance.status();
                setTimeout(done, 10);
            });
        });

        it("#restart() should send SIGUSR2", function (done) {
            var instance = new ComboMaster({ pids: PIDS_DIR });

            instance._signalMaster = function (signal) {
                signal.should.equal('SIGUSR2');
                done();
            };

            instance.emit('start', function () {
                instance._detachEvents();
                instance.restart();
            });
        });

        it("#shutdown() should send SIGTERM", function (done) {
            var instance = new ComboMaster({ pids: PIDS_DIR });

            instance._signalMaster = function (signal) {
                signal.should.equal('SIGTERM');
                done();
            };

            instance.emit('start', function () {
                instance._detachEvents();
                instance.shutdown();
            });
        });

        it("#stop() should send SIGKILL", function (done) {
            var instance = new ComboMaster({ pids: PIDS_DIR });

            instance._signalMaster = function (signal) {
                signal.should.equal('SIGKILL');
                done();
            };

            instance.emit('start', function () {
                instance._detachEvents();
                instance.stop();
            });
        });
    });

    describe("handling cluster events", function () {
        // ensure pids dir exists, no master pids created in these tests
        before(function (done) {
            mkdirp(PIDS_DIR, done);
        });
        after(cleanPidsDir);

        var mockWorkerIds = 0;
        function MockWorker() {
            var id = mockWorkerIds++;
            this.id = id;
            this.process = {
                pid: 1e6 + id
            };
        }
        MockWorker.prototype.send = function (payload) {
            this._sent = payload;
        };
        MockWorker.prototype.destroy = function () {
            this._destroyed = true;
        };

        it("should set startupTimeout when worker forked", function () {
            var instance = new ComboMaster({ timeout: 10 });
            var worker = new MockWorker();

            instance.startupTimeout.should.be.empty;
            instance._workerForked(worker);
            instance.startupTimeout.should.have.length(1);
        });

        it("should clear startupTimeout when worker online");

        it("should send 'listen' command when worker online", function () {
            var instance = new ComboMaster();
            var worker = new MockWorker();

            instance._workerOnline(worker);

            worker._sent.should.eql({
                cmd: 'listen',
                data: instance.options
            });
        });

        it("should write worker pidfile after worker listening", function () {
            var instance = new ComboMaster({ pids: PIDS_DIR });
            var worker = new MockWorker();

            instance._workerListening(worker);

            worker.process.should.have.property('title', 'combohandler worker');

            fs.existsSync(path.join(instance.options.pids, 'worker' + worker.id + '.pid'));
        });

        it("should set closingTimeout when worker disconnected", function () {
            var instance = new ComboMaster({ timeout: 10 });
            var worker = new MockWorker();

            instance.closingTimeout.should.be.empty;
            instance._workerDisconnected(worker);
            // timeouts aren't pushed onto the stack, they are assigned at the id's index
            instance.closingTimeout.should.have.length(worker.id + 1);
        });

        it("should destroy() worker when closingTimeout expires", function (done) {
            this.timeout(100);

            var instance = new ComboMaster({ timeout: 10 });
            var worker = new MockWorker();

            instance._workerDisconnected(worker);

            setTimeout(function () {
                worker.should.have.property('_destroyed', true);
                done();
            }, 25);
        });

        it("should clear startupTimeout when worker exited");

        it("should clear closingTimeout when worker exited");

        it("should not fork a new worker when worker suicides");

        it("should remove worker pidfile when worker suicides", function () {
            this.timeout(100);

            var instance = new ComboMaster({ pids: PIDS_DIR });
            var worker = new MockWorker();

            instance._workerListening(worker);

            worker.suicide = true;

            instance._workerExited(worker);

            fs.readdirSync(instance.options.pids).should.not.include('worker' + worker.id + '.pid');
        });

        it("should remove worker pidfile when worker is reloaded");

        it("should exit when flameouts threshhold exceeded");
    });

    describe("on 'listen'", function () {
        // disconnect called from #destroy() cleans the pids

        it("should fork workers", function (done) {
            this.timeout(0);

            var instance = new ComboMaster({
                workers: 1,
                pids: PIDS_DIR
            });

            instance.on('listen', function () {
                setTimeout(function () {
                    instance.destroy(done);
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

    function cleanPidsDir(done) {
        rimraf(PIDS_DIR, done);
    }
});
