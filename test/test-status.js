/*global describe, beforeEach, afterEach, it, sinon */
var checkStatus = require('../lib/cluster/status');

describe("cluster status", function () {
    /*jshint expr:true */

    beforeEach(function () {
        sinon.stub(console, "error");
        sinon.stub(process, "kill");
        sinon.stub(process, "exit");
    });

    afterEach(function () {
        console.error.restore();
        process.kill.restore();
        process.exit.restore();
    });

    it("should log healthy master", function () {
        checkStatus("master", 100);
        assertStatus("master", 100, "alive");
    });

    it("should increment numeric suffix", function () {
        checkStatus("worker", 100, 0);
        assertStatus("worker1", 100, "alive");
    });

    it("should exit when master dead", function () {
        process.kill.throws({ code: "ESRCH" });
        checkStatus("master", 100);
        assertStatus("master", 100, "dead");
        process.exit.calledWith(1).should.be.ok;
    });

    it("should not exit when worker dead", function () {
        process.kill.throws({ code: "ESRCH" });
        checkStatus("worker", 100, 0);
        assertStatus("worker1", 100, "dead");
        process.exit.callCount.should.equal(0);
    });

    it("should throw non-ESRCH errors", function () {
        process.kill.throws({ code: "FOO" });
        /*jshint immed:false */
        (function () {
            checkStatus("master", 100);
        }).should.throwError();
    });

    it("should iterate over workers", function () {
        [100, 200, 300].forEach(checkStatus.bind(null, "worker"));
        assertStatus("worker1", 100, "alive");
        assertStatus("worker2", 200, "alive");
        assertStatus("worker3", 300, "alive");
    });

    function assertStatus(name, pid, status) {
        var color = (status === 'alive') ? '36' : '31';
        var template = '%s\033[90m %d\033[0m \033[' + color + 'm%s\033[0m';
        console.error.calledWith(template, name, pid, status).should.be.ok;
    }
});
