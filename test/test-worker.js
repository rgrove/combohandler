/*global describe, before, after, it */

var ComboWorker = require('../lib/cluster/worker');

describe("cluster worker", function () {
    describe("instantiation", function () {
        it("should support factory-style (no new)");
        it("should merge defaults with passed options");
    });

    describe("#start()", function () {
        it("should start");
    });

    describe("#listen()", function () {
        it("should listen");
    });
});
