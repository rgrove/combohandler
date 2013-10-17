/*global describe, before, after, beforeEach, afterEach, it, sinon */
var fs = require('fs');
var path = require('path');
var mkdirp = require('mkdirp');
var rimraf = require('rimraf');
var should = require('should');

var pidfiles = require('../lib/cluster/pidfiles');

describe("pidfiles", function () {
    /*jshint expr:true */

    var PIDS_DIR = 'test/fixtures/pids';

    describe("#getMasterPid()", function () {
        beforeEach(function () {
            sinon.stub(fs, "readFile");
        });
        afterEach(function () {
            fs.readFile.restore();
        });

        it("should read master.pid", function (done) {
            fs.readFile.yields(null, 0, PIDS_DIR);

            pidfiles.getMasterPid(PIDS_DIR, function (err, pid, dir) {
                should.not.exist(err);
                pid.should.equal(0);
                dir.should.equal(PIDS_DIR);
                done();
            });
        });

        it("should pass fs error to callback", function (done) {
            fs.readFile.yields("foo");

            pidfiles.getMasterPid(PIDS_DIR, function (err) {
                should.exist(err);
                err.should.equal("foo");
                done();
            });
        });
    });

    describe("#getWorkerPidsSync()", function () {
        beforeEach(function () {
            sinon.stub(fs, "readdirSync");
            sinon.stub(fs, "readFileSync");
        });
        afterEach(function () {
            fs.readdirSync.restore();
            fs.readFileSync.restore();
        });

        it("should return worker pids only", function () {
            fs.readdirSync
                .withArgs(PIDS_DIR)
                .returns(["master.pid", "worker1.pid"]);

            fs.readFileSync
                .withArgs(path.join(PIDS_DIR, "worker1.pid"))
                .returns("1");

            pidfiles.getWorkerPidsSync(PIDS_DIR)
                .should.have.length(1)
                    .and.contain(1);
        });
    });

    describe("#removePidFile()", function () {
        beforeEach(function () {
            sinon.stub(fs, "unlink");
        });
        afterEach(function () {
            fs.unlink.restore();
        });

        it("should remove designated pidfile", function (done) {
            fs.unlink.yields(null);

            pidfiles.removePidFile(PIDS_DIR, "worker1", done);
        });

        it("should not require callback", function () {
            fs.unlink
                .withArgs(path.join(PIDS_DIR, "worker1.pid"))
                .yields(null);

            /*jshint immed:false */
            (function () {
                pidfiles.removePidFile(PIDS_DIR, "worker1");
            }).should.not.throwError();
        });

        it("should pass errors to callback", function () {
            fs.unlink
                .withArgs(path.join(PIDS_DIR, "worker1.pid"), sinon.match.func)
                .yields({ code: "ENOENT" });

            fs.unlink
                .withArgs(path.join(PIDS_DIR, "worker2.pid"), sinon.match.func)
                .yields({ code: "FOO" });

            pidfiles.removePidFile(PIDS_DIR, "worker1", function (err) {
                should.exist(err);
                err.should.have.property("code", "ENOENT");
            });

            pidfiles.removePidFile(PIDS_DIR, "worker2", function (err) {
                should.exist(err);
                err.should.have.property("code", "FOO");
            });
        });

        it("should log ENOENT errors", function () {
            var consoleError = sinon.stub(console, "error");
            fs.unlink.yields({ code: "ENOENT" });

            pidfiles.removePidFile(PIDS_DIR, "worker1");

            consoleError.calledOnce.should.be.ok;
            consoleError.calledWith('Could not find pidfile: %s', "worker1.pid");
            consoleError.restore();
        });

        it("should throw other errors", function () {
            fs.unlink.yields({ code: "FOO" });

            /*jshint immed:false */
            (function () {
                pidfiles.removePidFile(PIDS_DIR, "worker1");
            }).should.throwError();
        });
    });

    describe("#removePidFileSync()", function () {
        beforeEach(function () {
            sinon.stub(fs, "unlinkSync");
        });
        afterEach(function () {
            fs.unlinkSync.restore();
        });

        it("should remove designated pidfile", function () {
            pidfiles.removePidFileSync(PIDS_DIR, "worker1");

            fs.unlinkSync.calledOnce.should.be.ok;
            fs.unlinkSync.calledWith(path.join(PIDS_DIR, "worker1.pid")).should.be.ok;
        });
    });

    describe("#removeWorkerPidFiles()", function () {
        beforeEach(function () {
            sinon.stub(fs, "readdirSync");
        });
        afterEach(function () {
            fs.readdirSync.restore();
        });

        describe("without workers", function () {
            beforeEach(function () {
                fs.readdirSync
                    .withArgs(PIDS_DIR)
                    .returns([
                        "master.pid"
                    ]);
            });

            it("should callback immediately", function (done) {
                pidfiles.removeWorkerPidFiles(PIDS_DIR, done);
            });
        });

        describe("workers present", function () {
            beforeEach(function () {
                sinon.stub(pidfiles, "removePidFile");
                fs.readdirSync
                    .withArgs(PIDS_DIR)
                    .returns([
                        "master.pid",
                        "worker1.pid",
                        "worker2.pid"
                    ]);
            });
            afterEach(function () {
                pidfiles.removePidFile.restore();
            });

            describe("with callback", function () {
                it("should succeed", function (done) {
                    pidfiles.removePidFile.yields(null);
                    pidfiles.removeWorkerPidFiles(PIDS_DIR, done);
                });

                it("should log ENOENT errors", function (done) {
                    var consoleError = sinon.stub(console, "error");

                    pidfiles.removePidFile.yields(null);
                    pidfiles.removePidFile
                        .withArgs(PIDS_DIR, "worker1", sinon.match.func)
                        .yields({ code: "ENOENT" });

                    pidfiles.removeWorkerPidFiles(PIDS_DIR, function (err) {
                        should.not.exist(err);

                        pidfiles.removePidFile.calledTwice.should.be.ok;

                        consoleError.calledOnce.should.be.ok;
                        consoleError.calledWith('Could not find pidfile: %s', "worker1.pid");
                        consoleError.restore();

                        done();
                    });
                });

                it("should pass other errors to callback", function (done) {
                    pidfiles.removePidFile.yields(null);
                    pidfiles.removePidFile
                        .withArgs(PIDS_DIR, "worker1", sinon.match.func)
                        .yields({ code: "FOO" });

                    pidfiles.removeWorkerPidFiles(PIDS_DIR, function (err) {
                        should.exist(err);
                        err.should.have.property("code", "FOO");

                        pidfiles.removePidFile.calledOnce.should.be.ok;

                        done();
                    });
                });
            });

            describe("without callback", function () {
                it("should succeed", function () {
                    pidfiles.removePidFile.yields(null);
                    pidfiles.removeWorkerPidFiles(PIDS_DIR);
                    pidfiles.removePidFile.calledTwice.should.be.ok;
                });

                it("should log ENOENT errors", function () {
                    var consoleError = sinon.stub(console, "error");

                    pidfiles.removePidFile.yields(null);
                    pidfiles.removePidFile
                        .withArgs(PIDS_DIR, "worker1", sinon.match.func)
                        .yields({ code: "ENOENT" });

                    pidfiles.removeWorkerPidFiles(PIDS_DIR);
                    pidfiles.removePidFile.calledTwice.should.be.ok;

                    consoleError.calledOnce.should.be.ok;
                    consoleError.calledWith('Could not find pidfile: %s', "worker1.pid");
                    consoleError.restore();
                });

                it("should swallow other errors", function () {
                    pidfiles.removePidFile.yields(null);
                    pidfiles.removePidFile
                        .withArgs(PIDS_DIR, "worker1", sinon.match.func)
                        .yields({ code: "FOO" });

                    pidfiles.removeWorkerPidFiles(PIDS_DIR);
                    pidfiles.removePidFile.calledTwice.should.be.ok;
                });
            });
        });
    });

    describe("#writePidFileSync()", function () {
        beforeEach(function () {
            sinon.stub(fs, "existsSync");
            sinon.stub(fs, "writeFileSync");
            sinon.stub(mkdirp, "sync");
        });
        afterEach(function () {
            fs.existsSync.restore();
            fs.writeFileSync.restore();
            mkdirp.sync.restore();
        });

        it("should create directory if necessary", function () {
            fs.existsSync.returns(false);
            pidfiles.writePidFileSync(PIDS_DIR, "master", 0);

            mkdirp.sync.calledOnce.should.be.ok;
            mkdirp.sync.calledWith(PIDS_DIR).should.be.ok;

            fs.writeFileSync.calledOnce.should.be.ok;
            fs.writeFileSync.calledWith(path.join(PIDS_DIR, "master.pid"), "0").should.be.ok;
        });

        it("should write pidfile successfully", function () {
            fs.existsSync.returns(true);
            pidfiles.writePidFileSync(PIDS_DIR, "master", 0);

            fs.writeFileSync.calledOnce.should.be.ok;
            fs.writeFileSync.calledWith(path.join(PIDS_DIR, "master.pid"), "0").should.be.ok;
        });

        it("should default 'nameless' pidfile to master.pid", function () {
            fs.existsSync.returns(true);
            pidfiles.writePidFileSync(PIDS_DIR, "", 0);

            fs.writeFileSync.calledOnce.should.be.ok;
            fs.writeFileSync.calledWith(path.join(PIDS_DIR, "master.pid"), "0").should.be.ok;
        });
    });
});
