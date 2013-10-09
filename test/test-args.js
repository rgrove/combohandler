/*global describe, it, sinon */
var path = require('path');
var args = require('../lib/args');

describe("args", function () {
    /*jshint expr:true */

    describe("parse()", function () {
        it("should consume ad-hoc string 'restart' param as boolean config.restart", function () {
            var config = args.parse(['restart'], 0);

            config.restart.should.equal(true);
            config.should.not.have.property('shutdown');
            config.should.not.have.property('status');
            config.should.not.have.property('stop');
        });

        it("should consume ad-hoc string 'shutdown' param as boolean config.shutdown", function () {
            var config = args.parse(['shutdown'], 0);

            config.should.not.have.property('restart');
            config.shutdown.should.equal(true);
            config.should.not.have.property('status');
            config.should.not.have.property('stop');
        });

        it("should consume ad-hoc string 'status' param as boolean config.status", function () {
            var config = args.parse(['status'], 0);

            config.should.not.have.property('restart');
            config.should.not.have.property('shutdown');
            config.status.should.equal(true);
            config.should.not.have.property('stop');
        });

        it("should consume ad-hoc string 'stop' param as boolean config.stop", function () {
            var config = args.parse(['stop'], 0);

            config.should.not.have.property('restart');
            config.should.not.have.property('shutdown');
            config.should.not.have.property('status');
            config.stop.should.equal(true);
        });

        describe("with augmented knownOpts", function () {
            args.knownOpts["ad-hoc-path"] = path;
            args.knownOpts["ad-hoc-many"] = [String, Array];

            it("should parse --ad-hoc-path as a resolved path", function () {
                var config = args.parse(['--ad-hoc-path', './test/fixtures'], 0);

                config.should.have.property('ad-hoc-path');
                config['ad-hoc-path'].should.equal(path.resolve(__dirname, 'fixtures'));
            });

            it("should parse --ad-hoc-many as an array of strings", function () {
                var config = args.parse([
                    '--ad-hoc-many', 'foo',
                    '--ad-hoc-many', 'bar',
                    '--ad-hoc-many', 'baz'
                ], 0);

                config.should.have.property('ad-hoc-many');
                config['ad-hoc-many'].should.eql(['foo', 'bar', 'baz']);
            });
        });

        describe("with augmented shortHands", function () {
            args.shortHands.foo = ["--ad-hoc-path", "./test/fixtures"];

            it("should parse --foo as '--ad-hoc-path ./test/fixtures'", function () {
                var config = args.parse(['--foo'], 0);

                config.should.have.property('ad-hoc-path');
                config['ad-hoc-path'].should.equal(path.resolve(__dirname, 'fixtures'));
            });
        });
    });

    describe("clean()", function () {
        it("should clean options in-place", function () {
            var config = {
                server: 'foo/bar.js'
            };

            args.clean(config);

            config.server.should.equal(path.resolve('foo/bar.js'));
        });

        it("should return clean options object", function () {
            var config = { port: '1234' },
                cleaned = args.clean(config);

            cleaned.port.should.equal(1234);
            config.should.equal(cleaned);
        });
    });

    describe("resolveRoots()", function () {
        it("should resolve route paths from dirname of rootsFile", function () {
            var config = args.clean({
                rootsFile: 'test/root.json'
            });

            config.should.have.property('roots');

            // route
            config.roots.should.have.property('/css');
            config.roots.should.have.property('/js');

            // rootPath
            config.roots['/css'].should.equal(path.resolve('test/fixtures/root/css'));
            config.roots['/js' ].should.equal(path.resolve('test/fixtures/root/js' ));
        });

        it("should just ignore rootsFile when it is a directory", function () {
            var config = args.clean({ rootsFile: __dirname });

            config.should.not.have.property('roots');
        });

        it("should throw error when rootsFile does not exist", function () {
            /*jshint immed:false */
            (function () {
                args.clean({ rootsFile: 'test/missing.json' });
            }).should.throwError(/^ENOENT/);
        });

        it("should process --root options, if present", function () {
            var config = args.clean({
                root: [
                    "/css:test/fixtures/root/css",
                    "/js:test/fixtures/root/js"
                ]
            });

            config.should.have.property('roots');

            config.roots.should.eql({
                "/css": path.resolve('test/fixtures/root/css'),
                "/js" : path.resolve('test/fixtures/root/js' )
            });
        });

        it("should process --root options with route parameters correctly", function () {
            var config = args.clean({
                root: [
                    "/:begin/combo:test/fixtures/dynamic/:begin/static",
                    // TODO: actually support multiple dynamic route parameters
                    "/:holy/:moly/combo:test/fixtures/dynamic/:holy/:moly/static",
                    "/combo/:ending:test/fixtures/dynamic/:ending"
                ]
            });

            config.should.have.property('roots');

            config.roots.should.eql({
                "/:begin/combo": path.resolve('test/fixtures/dynamic/:begin/static'),
                "/:holy/:moly/combo": path.resolve('test/fixtures/dynamic/:holy/:moly/static'),
                "/combo/:ending": path.resolve('test/fixtures/dynamic/:ending')
            });
        });
    });

    describe("usage()", function () {
        it("should output string joined with newlines", function () {
            var usage = args.usage;
            usage.should.not.be.empty;
            usage.split('\n').length.should.be.above(5);
        });
    });

    describe("version()", function () {
        it("should read package.json for correct value", function () {
            var pkgVersion = require('../package.json').version;
            var gotVersion = args.version;

            gotVersion.should.equal(pkgVersion);
        });
    });

    describe("invoke()", function () {
        function assertMethodCalled(methodName) {
            return function (done) {
                var instance = {
                    options: {}
                };
                instance[methodName] = done;
                instance.options[methodName] = true;

                args.invoke(instance);
            };
        }

        it("should call restart() when options.restart present",    assertMethodCalled("restart"));
        it("should call shutdown() when options.shutdown present",  assertMethodCalled("shutdown"));
        it("should call status() when options.status present",      assertMethodCalled("status"));
        it("should call stop() when options.stop present",          assertMethodCalled("stop"));
        it("should call listen() when no other options present",    assertMethodCalled("listen"));
    });
});
