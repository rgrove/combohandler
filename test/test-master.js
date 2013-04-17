/*global describe, before, after, it */

var ComboBase = require('../lib/cluster/base');
var ComboMaster = require('../lib/cluster');

describe("cluster master", function () {
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
    });

    describe("on 'start'", function () {
        it("should setupMaster");
        it("should create master.pid");
        it("should attach events");
    });

    describe("on 'destroy'", function () {
        it("should detach events, passing through callback");
        it("should not error when detachEvents callback missing");
    });

    describe("on 'listen'", function () {
        it("should fork workers");
    });
});
