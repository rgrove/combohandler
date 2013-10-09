/*global describe, before, after, it, sinon */
var fs = require('fs');
var path = require('path');

var combo   = require('../'),
    server  = require('../lib/server'),

    assert  = require('assert'),
    request = require('request'),

    PORT     = 8942,
    BASE_URL = 'http://localhost:' + PORT;

process.env.NODE_ENV = 'test';

describe('combohandler', function () {
    /*jshint expr:true */

    var app, httpServer;

    before(function (done) {
        app = server({
            roots: {
                '/css': __dirname + '/fixtures/root/css',
                '/js' : __dirname + '/fixtures/root/js'
            }
        });

        httpServer = app.listen(PORT, done);
    });

    after(function (done) {
        httpServer.close(done);
    });

    it("should return an array of middleware callbacks when invoked", function () {
        var callbacks = combo.combine();
        callbacks.should.be.an.instanceOf(Array);
        callbacks.should.have.lengthOf(1);
        callbacks[0].name.should.equal('combineMiddleware');
    });

    it('should combine JavaScript', function (done) {
        request(BASE_URL + '/js?a.js&b.js', function (err, res, body) {
            assert.ifError(err);
            res.should.have.status(200);
            res.should.have.header('content-type', 'application/javascript; charset=utf-8');
            res.should.have.header('last-modified');
            body.should.equal('a();\n\nb();\n');
            done();
        });
    });

    it('should combine CSS', function (done) {
        request(BASE_URL + '/css?a.css&b.css', function (err, res, body) {
            assert.ifError(err);
            res.should.have.status(200);
            res.should.have.header('content-type', 'text/css; charset=utf-8');
            res.should.have.header('last-modified');
            body.should.equal('.a { color: green; }\n\n.b { color: green; }\n');
            done();
        });
    });

    it('should support symlinks pointing outside the root', function (done) {
        request(BASE_URL + '/js?a.js&b.js&outside.js', function (err, res, body) {
            assert.ifError(err);
            res.should.have.status(200);
            res.should.have.header('content-type', 'application/javascript; charset=utf-8');
            res.should.have.header('last-modified');
            body.should.equal('a();\n\nb();\n\noutside();\n');
            done();
        });
    });

    // -- Config Options -------------------------------------------------------
    describe('config: maxAge', function () {
        before(function () {
            app.get('/max-age-null', combo.combine({
                rootPath: __dirname + '/fixtures/root/js',
                maxAge  : null
            }), combo.respond);

            app.get('/max-age-0', combo.combine({
                rootPath: __dirname + '/fixtures/root/js',
                maxAge  : 0
            }), combo.respond);
        });

        it('should default to one year', function (done) {
            request(BASE_URL + '/js?a.js', function (err, res, body) {
                assert.ifError(err);
                res.should.have.status(200);
                res.should.have.header('cache-control', 'public,max-age=31536000');

                res.headers.should.have.property('expires');
                var expires = new Date(res.headers.expires);
                ((expires - Date.now()) / 1000).should.be.within(31535990, 31536000);

                done();
            });
        });

        it('should not set Cache-Control and Expires headers when maxAge is null', function (done) {
            request(BASE_URL + '/max-age-null?a.js', function (err, res, body) {
                assert.ifError(err);
                res.should.have.status(200);
                res.headers.should.not.have.property('cache-control');
                res.headers.should.not.have.property('expires');
                done();
            });
        });

        it('should support a maxAge of 0', function (done) {
            request(BASE_URL + '/max-age-0?a.js', function (err, res, body) {
                assert.ifError(err);
                res.should.have.status(200);
                res.should.have.header('cache-control', 'public,max-age=0');

                res.headers.should.have.property('expires');
                var expires = new Date(res.headers.expires);
                ((expires - Date.now()) / 1000).should.be.within(-5, 5);

                done();
            });
        });
    });

    describe('config: errorMaxAge', function () {
        before(function () {
            function throwBadRequest(req, res, next) {
                next(new combo.BadRequest('errorMaxAge'));
            }

            app.use('/error-max-age-null', throwBadRequest);
            app.use('/error-max-age-null', combo.errorHandler({
                errorMaxAge: null
            }));

            app.use('/error-max-age-0', throwBadRequest);
            app.use('/error-max-age-0', combo.errorHandler({
                errorMaxAge: 0
            }));
        });

        it('should default to five minutes', function (done) {
            request(BASE_URL + '/js?err.js', function (err, res, body) {
                res.should.have.status(400);
                res.should.have.header('cache-control', 'public,max-age=300');

                res.headers.should.have.property('expires');
                var expires = new Date(res.headers.expires);
                ((expires - Date.now()) / 1000).should.be.within(290, 300);

                done();
            });
        });

        it('should set private Cache-Control and no-cache headers when errorMaxAge is null', function (done) {
            request(BASE_URL + '/error-max-age-null?a.js', function (err, res, body) {
                assert.ifError(err);
                res.should.have.status(400);
                res.should.have.header('cache-control', 'private,no-store');
                res.should.have.header('pragma', 'no-cache');

                res.headers.should.have.property('expires');
                var expires = new Date(res.headers.expires).getTime();
                expires.should.equal(new Date(0).getTime());

                done();
            });
        });

        it('should support an errorMaxAge of 0', function (done) {
            request(BASE_URL + '/error-max-age-0?a.js', function (err, res, body) {
                assert.ifError(err);
                res.should.have.status(400);
                res.should.have.header('cache-control', 'public,max-age=0');

                res.headers.should.have.property('expires');
                var expires = new Date(res.headers.expires);
                ((expires - Date.now()) / 1000).should.be.within(-5, 5);

                done();
            });
        });
    });

    describe('config: basePath', function () {
        describe('when absent', function () {
            it("should NOT append cssUrls middleware to callbacks", function () {
                var callbacks = combo.combine();
                callbacks.should.have.lengthOf(1);
                callbacks[0].name.should.not.equal('cssUrlsMiddleware');
            });
        });

        describe('when present', function () {
            it("should append cssUrls middleware to callbacks", function () {
                var callbacks = combo.combine({ basePath: 'foo' });
                callbacks.should.have.lengthOf(2);
                callbacks[1].name.should.equal('cssUrlsMiddleware');
            });
        });
    });

    describe('config: webRoot', function () {
        describe('when absent', function () {
            it("should NOT append cssUrls middleware to callbacks", function () {
                var callbacks = combo.combine();
                callbacks.should.have.lengthOf(1);
                callbacks[0].name.should.not.equal('cssUrlsMiddleware');
            });
        });

        describe('when present', function () {
            it("should append cssUrls middleware to callbacks", function () {
                var callbacks = combo.combine({ webRoot: 'foo' });
                callbacks.should.have.lengthOf(2);
                callbacks[1].name.should.equal('cssUrlsMiddleware');
            });
        });
    });

    describe('config: rootPath', function () {
        it("should error when value does not exist", function () {
            /*jshint immed: false */
            (function () {
                combo.combine({ rootPath: '/foo' });
            }).should.throwError();
        });

        describe('with route parameters', function () {
            it("should prepend dynamicPath middleware to callbacks", function () {
                var callbacks = combo.combine({ rootPath: __dirname + '/fixtures/:root/js' });
                callbacks.should.have.lengthOf(2);
                callbacks[0].name.should.equal('dynamicPathMiddleware');
            });
        });
    });

    // -- Errors ---------------------------------------------------------------
    describe('errors', function () {
        before(function () {
            app.get('/error-next?', function (req, res, next) {
                var poo = new Error('poo');
                poo.stack = null; // silence irrelevant output
                next(poo);
            }, combo.combine({
                rootPath: __dirname + '/fixtures/root/js'
            }), combo.respond);

            app.get('/error-throw?', combo.combine({
                rootPath: __dirname + '/fixtures/root/js'
            }), function (req, res, next) {
                throw 'poo';
            }, combo.respond);
        });

        it('should inherit from Error', function () {
            var err = new combo.BadRequest('test');
            err.should.be.an.instanceOf(Error);
            err.name.should.equal('BadRequest');
            err.message.should.equal('test');
        });

        it('should return a 500 when error before middleware', function (done) {
            request(BASE_URL + '/error-next?a.js', function (err, res, body) {
                assert.ifError(err);
                res.should.have.status(500);
                done();
            });
        });

        it('should return a 500 when error after middleware', function (done) {
            request(BASE_URL + '/error-throw?a.js', function (err, res, body) {
                assert.ifError(err);
                res.should.have.status(500);
                done();
            });
        });

        it('should return a 400 Bad Request error when no files are specified', function (done) {
            request(BASE_URL + '/js', function (err, res, body) {
                assert.ifError(err);
                res.should.have.status(400);
                body.should.equal('Bad request. No files requested.');
                done();
            });
        });

        it('should throw a 400 Bad Request error when a file is not found', function (done) {
            request(BASE_URL + '/js?bogus.js', function (err, res, body) {
                assert.ifError(err);
                res.should.have.status(400);
                res.should.have.header('content-type', 'text/plain; charset=utf-8');
                body.should.equal('Bad request. File not found: bogus.js');
                done();
            });
        });

        it('should throw a 400 Bad Request error when a white-listed MIME type is not found', function (done) {
            request(BASE_URL + '/js?foo.bar', function (err, res, body) {
                assert.ifError(err);
                res.should.have.status(400);
                body.should.equal('Bad request. Illegal MIME type present.');
                done();
            });
        });

        it('should throw a 400 Bad Request error when an unmapped MIME type is found with other valid types', function (done) {
            request(BASE_URL + '/js?a.js&foo.bar', function (err, res, body) {
                assert.ifError(err);
                res.should.have.status(400);
                body.should.equal('Bad request. Only one MIME type allowed per request.');
                done();
            });
        });

        it('should throw a 400 Bad Request error when more than one valid MIME type is found', function (done) {
            request(BASE_URL + '/js?a.js&b.css', function (err, res, body) {
                assert.ifError(err);
                res.should.have.status(400);
                body.should.equal('Bad request. Only one MIME type allowed per request.');
                done();
            });
        });

        it('should throw a 400 Bad Request error when a querystring is truncated', function (done) {
            request(BASE_URL + '/js?a.js&b', function (err, res, body) {
                assert.ifError(err);
                res.should.have.status(400);
                body.should.equal('Bad request. Truncated query parameters.');
                done();
            });
        });

        it('should throw a 400 Bad Request error when a querystring is dramatically truncated', function (done) {
            request(BASE_URL + '/js?a', function (err, res, body) {
                assert.ifError(err);
                res.should.have.status(400);
                body.should.equal('Bad request. Truncated query parameters.');
                done();
            });
        });

        describe('path traversal', function () {
            var paths = [
                '../../../../package.json',
                '..%2f..%2f..%2f..%2fpackage.json',
                '%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fpackage.json',
                '%2e%2e/%2e%2e/%2e%2e/%2e%2e/package.json',
                '..\\..\\..\\..\\package.json',
                '..%5c..%5c..%5c..%5cpackage.json',
                '%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5cpackage.json',
                '%2e%2e\\%2e%2e\\%2e%2e\\%2e%2e\\package.json',
                '....//....//....//....//package.json',
                '....%2f%2f....%2f%2f....%2f%2f....%2f%2fpackage.json',
                '....\\\\....\\\\....\\\\....\\\\package.json',
                '....%5c%5c....%5c%5c....%5c%5c....%5c%5cpackage.json'
            ];

            paths.forEach(function (path) {
                it('should throw a 400 Bad Request error when path traversal is attempted: ' + path, function (done) {
                    request(BASE_URL + '/js?' + path, function (err, res, body) {
                        assert.ifError(err);
                        res.should.have.status(400);
                        res.should.have.header('content-type', 'text/plain; charset=utf-8');
                        body.should.match(/^Bad request. File not found: /);
                        done();
                    });
                });
            });
        });
    });

    // -- Optional Middleware --------------------------------------------------
    describe("url rewrites", function () {
        var TEMPLATE_URLS = [
            "#shorthand { background: transparent left top no-repeat url(__PATH__shorthand.png);}",
            "#no-quotes { background: url(__PATH__no-quotes.png);}",
            "#single-quotes { background: url(\'__PATH__single-quotes.png\');}",
            "#double-quotes { background: url(\"__PATH__double-quotes.png\");}",
            "#spaces { background: url(",
            "  \"__PATH__spaces.png\" );}",
            "#data-url { background: url(data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==);}",
            "#absolute-url { background: url(http://www.example.com/foo.gif?a=b&c=d#bebimbop);}",
            "#protocol-relative-url { background: url(//www.example.com/foo.gif?a=b&c=d#bebimbop);}",
            "#escaped-stuff { background:url(\"__PATH__\\)\\\";\\'\\(.png\"); }",
            ".unicode-raw { background: url(__PATH__déchaîné.png); }",
            // NOTE: we do not currently support the space terminator for CSS escapes.
            // ".unicode-escaped { background: url(__PATH__d\\E9 cha\\EEn\\E9.png); }",
            ".unicode-escaped { background: url(__PATH__d\\0000E9cha\\EEn\\E9.png); }",
            ".nl-craziness { background:",
            "    url(__PATH__crazy.png",
            "    ); }",
            ""
        ].join("\n");

        var TEMPLATE_MORE = [
            "#depth { background: url(__PATH__deeper/deeper.png);}",
            "#up-one { background: url(__PATH__shallower.png);}",
            "#down-one { background: url(__PATH__deeper/more/down-one.png);}"
        ].join("\n");

        var TEMPLATE_IMPORTS = [
            "@import '__PATH__basic-sq.css';",
            "@import \"__PATH__basic-dq.css\";",
            "@import url(__PATH__url-uq.css);",
            "@import url('__PATH__url-sq.css');",
            "@import url(\"__PATH__url-dq.css\");",
            "@import \"__PATH__media-simple.css\" print;",
            "@import url(\"__PATH__media-simple-url.css\") print;",
            "@import '__PATH__media-simple-comma.css' print, screen;",
            "@import \"__PATH__media-complex.css\" screen and (min-width: 400px) and (max-width: 700px);",
            "@import url(\"__PATH__media-complex-url.css\") screen and (min-width: 400px) and (max-width: 700px);",
            // TODO: are the following rewritten correctly?
            "@import \"__DOTS__/rewrite/deeper/more.css\";",
            "@import \"__DOTS__/root/css/a.css\" (device-width: 320px);",
            ""
        ].join("\n");

        var URLS_UNMODIFIED = TEMPLATE_URLS.replace(/__PATH__/g, '');
        var IMPORTS_UNMODIFIED = TEMPLATE_IMPORTS.replace(/__PATH__/g, '').replace(/__DOTS__/g, '..');

        function assertRequestBodyIs(reqPath, result, done) {
            request(BASE_URL + reqPath, function (err, res, body) {
                assert.ifError(err);
                body.should.equal(result);
                done();
            });
        }

        before(function () {
            app.get('/norewrite', combo.combine({
                rootPath: __dirname + '/fixtures/rewrite'
            }), combo.respond);

            app.get('/rewrite', combo.combine({
                rootPath: __dirname + '/fixtures/rewrite',
                basePath: "/rewritten/"
            }), combo.respond);

            app.get('/rewrite-noslash', combo.combine({
                rootPath: __dirname + '/fixtures/rewrite',
                basePath: "/rewritten"
            }), combo.respond);

            app.get('/rewrite-imports', combo.combine({
                rootPath: __dirname + '/fixtures/rewrite',
                basePath: "/rewritten/",
                rewriteImports: true
            }), combo.respond);

            app.get('/rewrite-middleware-before-combine',
                combo.cssUrls({ basePath: "/rewritten/" }),
                combo.combine({ rootPath: __dirname + '/fixtures/rewrite' }),
            combo.respond);

            app.get('/rewrite-middleware-noconfig',
                combo.combine({ rootPath: __dirname + '/fixtures/rewrite' }),
                combo.cssUrls(),
            combo.respond);

            app.get('/rewrite-root', combo.combine({
                rootPath: __dirname + '/fixtures/rewrite',
                webRoot:  __dirname + '/fixtures/'
            }), combo.respond);

            app.get('/rewrite-root-noslash', combo.combine({
                rootPath: __dirname + '/fixtures/rewrite',
                webRoot:  __dirname + '/fixtures'
            }), combo.respond);

            app.get('/rewrite-root-imports', combo.combine({
                rootPath: __dirname + '/fixtures/rewrite',
                webRoot:  __dirname + '/fixtures/',
                rewriteImports: true
            }), combo.respond);
        });

        it("should not rewrite without a basePath or webRoot", function (done) {
            assertRequestBodyIs("/norewrite?urls.css", URLS_UNMODIFIED, done);
        });

        it("should not rewrite without a basePath or webRoot as middleware", function (done) {
            assertRequestBodyIs("/rewrite-middleware-noconfig?urls.css", URLS_UNMODIFIED, done);
        });

        it("should not rewrite when middleware before combine()", function (done) {
            assertRequestBodyIs("/rewrite-middleware-before-combine?urls.css", URLS_UNMODIFIED, done);
        });

        describe("with configured basePath", function () {
            var URLS_REWRITTEN = TEMPLATE_URLS.replace(/__PATH__/g, '/rewritten/');
            var MORE_REWRITTEN = TEMPLATE_MORE.replace(/__PATH__/g, '/rewritten/');

            var MORE_URLS_REWRITTEN = [URLS_REWRITTEN, MORE_REWRITTEN].join("\n");

            var IMPORTS_REWRITTEN = TEMPLATE_IMPORTS.replace(/__PATH__/g, '/rewritten/')
                                                    .replace(/__DOTS__/g, '');

            it("should allow basePath without trailing slash", function (done) {
                assertRequestBodyIs("/rewrite-noslash?urls.css", URLS_REWRITTEN, done);
            });

            it("should rewrite valid urls", function (done) {
                assertRequestBodyIs("/rewrite?urls.css&deeper/more.css", MORE_URLS_REWRITTEN, done);
            });

            it("should NOT rewrite import paths when disabled", function (done) {
                assertRequestBodyIs("/rewrite?imports.css", IMPORTS_UNMODIFIED, done);
            });

            it("should rewrite import paths when enabled", function (done) {
                assertRequestBodyIs("/rewrite-imports?imports.css", IMPORTS_REWRITTEN, done);
            });
        });

        describe("with configured webRoot", function () {
            var URLS_REBASED = TEMPLATE_URLS.replace(/__PATH__/g, '/rewrite/');
            var MORE_REBASED = TEMPLATE_MORE.replace(/__PATH__/g, '/rewrite/');

            var MORE_URLS_REBASED = [URLS_REBASED, MORE_REBASED].join("\n");

            var IMPORTS_REBASED = TEMPLATE_IMPORTS.replace(/__PATH__/g, '/rewrite/')
                                                  .replace(/__DOTS__/g, '');

            it("should allow webRoot without trailing slash", function (done) {
                assertRequestBodyIs("/rewrite-root-noslash?urls.css", URLS_REBASED, done);
            });

            it("should rewrite valid urls", function (done) {
                assertRequestBodyIs("/rewrite-root?urls.css&deeper/more.css", MORE_URLS_REBASED, done);
            });

            it("should NOT rewrite import paths when disabled", function (done) {
                assertRequestBodyIs("/rewrite-root?imports.css", IMPORTS_UNMODIFIED, done);
            });

            it("should rewrite import paths when enabled", function (done) {
                assertRequestBodyIs("/rewrite-root-imports?imports.css", IMPORTS_REBASED, done);
            });
        });
    });

    describe("dynamic paths", function () {
        before(function () {
            app.get('/dynamic/:version',
                combo.combine({ rootPath: __dirname + '/fixtures/dynamic/:version' }),
            combo.respond);

            app.get('/:version/param-first',
                combo.combine({ rootPath: __dirname + '/fixtures/dynamic/:version' }),
            combo.respond);

            app.get('/dynamic/:version/empty-combo',
                combo.dynamicPath({ rootPath: __dirname + '/fixtures/dynamic/:version/static' }),
                combo.combine(),
            combo.respond);

            app.get('/dynamic/:version/doubled',
                combo.dynamicPath({ rootPath: __dirname + '/fixtures/dynamic/:version/static' }),
                combo.combine({     rootPath: __dirname + '/fixtures/dynamic/:version/static' }),
            combo.respond);

            app.get('/non-dynamic',
                combo.dynamicPath({ rootPath: __dirname + '/fixtures/dynamic/decafbad' }),
                combo.combine({     rootPath: __dirname + '/fixtures/dynamic/decafbad' }),
            combo.respond);

            app.get('/dynamic-no-config',
                combo.dynamicPath(),
                combo.combine({     rootPath: __dirname + '/fixtures/dynamic/decafbad' }),
            combo.respond);

            app.get('/route-only/:version/lib',
                combo.combine({ rootPath: __dirname + '/fixtures/root' }),
            combo.respond);
        });

        it("should work when param found at end of path", function (done) {
            request(BASE_URL + '/dynamic/decafbad?a.js&b.js', function (err, res, body) {
                assert.ifError(err);
                res.should.have.status(200);
                res.should.have.header('content-type', 'application/javascript; charset=utf-8');
                res.should.have.header('last-modified');
                body.should.equal('a();\n\nb();\n');
                done();
            });
        });

        it("should work when param found at beginning of path", function (done) {
            request(BASE_URL + '/decafbad/param-first?a.js&static/c.js', function (err, res, body) {
                assert.ifError(err);
                res.should.have.status(200);
                res.should.have.header('content-type', 'application/javascript; charset=utf-8');
                res.should.have.header('last-modified');
                body.should.equal('a();\n\nc();\n');
                done();
            });
        });

        it("should work when rootPath not passed to combine()", function (done) {
            request(BASE_URL + '/dynamic/decafbad/empty-combo?c.js&d.js', function (err, res, body) {
                assert.ifError(err);
                res.should.have.status(200);
                res.should.have.header('content-type', 'application/javascript; charset=utf-8');
                res.should.have.header('last-modified');
                body.should.equal('c();\n\nd();\n');
                done();
            });
        });

        it("should work when param found before end of path", function (done) {
            request(BASE_URL + '/dynamic/decafbad/empty-combo?c.js&d.js', function (err, res, body) {
                assert.ifError(err);
                res.should.have.status(200);
                res.should.have.header('content-type', 'application/javascript; charset=utf-8');
                res.should.have.header('last-modified');
                body.should.equal('c();\n\nd();\n');
                done();
            });
        });

        it("should work when middleware is run twice on same route", function (done) {
            request(BASE_URL + '/dynamic/decafbad/doubled?c.js&d.js', function (err, res, body) {
                assert.ifError(err);
                res.should.have.status(200);
                res.should.have.header('content-type', 'application/javascript; charset=utf-8');
                res.should.have.header('last-modified');
                body.should.equal('c();\n\nd();\n');
                done();
            });
        });

        it("should not fail when param not present", function (done) {
            request(BASE_URL + '/non-dynamic?a.js&b.js', function (err, res, body) {
                assert.ifError(err);
                res.should.have.status(200);
                res.should.have.header('content-type', 'application/javascript; charset=utf-8');
                res.should.have.header('last-modified');
                body.should.equal('a();\n\nb();\n');
                done();
            });
        });

        it("should not fail when config missing", function (done) {
            request(BASE_URL + '/dynamic-no-config?a.js&b.js', function (err, res, body) {
                assert.ifError(err);
                res.should.have.status(200);
                res.should.have.header('content-type', 'application/javascript; charset=utf-8');
                res.should.have.header('last-modified');
                body.should.equal('a();\n\nb();\n');
                done();
            });
        });

        it("should work when param only found in route, not rootPath", function (done) {
            request(BASE_URL + '/route-only/deadbeef/lib?js/a.js&js/b.js', function (err, res, body) {
                assert.ifError(err);
                res.should.have.status(200);
                res.should.have.header('content-type', 'application/javascript; charset=utf-8');
                res.should.have.header('last-modified');
                body.should.equal('a();\n\nb();\n');
                done();
            });
        });

        it("should error when param does not correspond to existing path", function (done) {
            request(BASE_URL + '/dynamic/deadbeef?a.js', function (err, res, body) {
                assert.ifError(err);
                res.should.have.status(400);
                body.should.equal('Bad request. Unable to resolve path: /dynamic/deadbeef');
                done();
            });
        });
    });

    // -- Complex Integration --------------------------------------------------
    describe("complex", function () {
        // Strange things may happen when you mix symlinks, parameters, and complex routes
        var COMPLEX_ROOT = __dirname + '/fixtures/complex';

        var TEMPLATE_IMPORTS_SIMPLE = [
            '@import "__ROOT__css/parent.css";',
            '@import "__ROOT__css/urls/child/dir.css";',
            '@import "__ROOT__css/urls/sibling.css";',
            '@import "__ROOT__css/urls/also-sibling.css";',
            ''
        ].join('\n');
        var TEMPLATE_URLS_SIMPLE = [
            '.relatives { background: url(__ROOT__images/cousin.png); }',
            '.offspring { background: url(__ROOT__css/urls/images/grandchild.png); }',
            ''
        ].join('\n');
        var TEMPLATE_SIMPLE = TEMPLATE_IMPORTS_SIMPLE + TEMPLATE_URLS_SIMPLE;

        var SIMPLE_IMPORTS_RAW = [
            '@import "../parent.css";',
            '@import "child/dir.css";',
            '@import "./sibling.css";',
            '@import "../urls/also-sibling.css";',
            ''
        ].join('\n');
        var SIMPLE_URLS_RAW = [
            '.relatives { background: url(../../images/cousin.png); }',
            '.offspring { background: url(./images/grandchild.png); }',
            ''
        ].join('\n');
        var SIMPLE_RAW = SIMPLE_IMPORTS_RAW + SIMPLE_URLS_RAW;

        function assertRequestSuccess(reqPath, done) {
            request(BASE_URL + reqPath, function (err, res, body) {
                assert.ifError(err);
                res.should.have.status(200);
                done();
            });
        }

        describe("route with fully-qualified dynamic path", function () {
            var combined = combo.combine({
                webRoot : COMPLEX_ROOT,
                rootPath: COMPLEX_ROOT + '/versioned/:version/base/'
            });

            it("should read rootPath from filesystem directly", function (done) {
                app.get("/c/:version/fs-fq", combined, function (req, res, next) {
                    var rootPath = res.locals.rootPath;
                    rootPath.should.equal(path.join(COMPLEX_ROOT, '/versioned/deeper/base/'));
                    next();
                }, combo.respond);

                assertRequestSuccess("/c/deeper/fs-fq?js/a.js&js/b.js", done);
            });

            it("should resolve rootPath through symlink", function (done) {
                app.get("/c/:version/ln-fq", combined, function (req, res, next) {
                    var rootPath = res.locals.rootPath;
                    rootPath.should.equal(path.join(COMPLEX_ROOT, '/versioned/shallower/base/'));

                    var relativePath = res.locals.relativePaths[0];
                    relativePath.should.equal('js/a.js');

                    fs.realpath(path.join(rootPath, relativePath), function (err, resolved) {
                        assert.ifError(err);
                        resolved.should.equal(path.join(COMPLEX_ROOT, '/base/', relativePath));
                        next();
                    });
                }, combo.respond);

                assertRequestSuccess("/c/shallower/ln-fq?js/a.js&js/b.js", done);
            });

            it("should only rewrite url() through symlink, not imports", function (done) {
                app.get("/c/:version/fq-noimports", combined, function (req, res, next) {
                    var rootPath = res.locals.rootPath;
                    rootPath.should.equal(path.join(COMPLEX_ROOT, '/versioned/shallower/base/'));

                    var relativePath = res.locals.relativePaths[0];
                    relativePath.should.equal('css/urls/simple.css');

                    // console.error(res.body);
                    var expected = (SIMPLE_IMPORTS_RAW + TEMPLATE_URLS_SIMPLE)
                                    .replace(/__ROOT__/g, '/versioned/shallower/base/');
                    res.body.should.equal(expected);

                    next();
                }, combo.respond);

                assertRequestSuccess("/c/shallower/fq-noimports?css/urls/simple.css", done);
            });
        });

        describe("route with one-sided dynamic path", function () {
            describe("and rootPath symlinked shallower", function () {
                var combined = combo.combine({
                    rewriteImports: true,
                    webRoot : COMPLEX_ROOT,
                    rootPath: COMPLEX_ROOT + '/versioned/shallower/base/'
                });

                it("should resolve files from realpath in filesystem", function (done) {
                    app.get("/c/:version/fs-shallow", combined, function (req, res, next) {
                        var rootPath = res.locals.rootPath;
                        rootPath.should.equal(path.join(COMPLEX_ROOT, '/base/'));

                        var relativePath = res.locals.relativePaths[0];
                        relativePath.should.equal('js/a.js');

                        fs.realpath(path.join(rootPath, relativePath), function (err, resolved) {
                            assert.ifError(err);
                            resolved.should.equal(path.join(COMPLEX_ROOT, '/base/', relativePath));
                            next();
                        });
                    }, combo.respond);

                    assertRequestSuccess("/c/cafebabe/fs-shallow?js/a.js&js/b.js", done);
                });

                it("should rewrite url() through symlink", function (done) {
                    app.get("/c/:version/ln-shallow", combined, function (req, res, next) {
                        var rootPath = res.locals.rootPath;
                        rootPath.should.equal(path.join(COMPLEX_ROOT, '/base/'));

                        var relativePath = res.locals.relativePaths[0];
                        relativePath.should.equal('css/urls/simple.css');

                        // console.error(res.body);
                        res.body.should.equal(TEMPLATE_SIMPLE.replace(/__ROOT__/g, '/base/'));

                        next();
                    }, combo.respond);

                    assertRequestSuccess("/c/cafebabe/ln-shallow?css/urls/simple.css", done);
                });
            });

            describe("and rootPath symlinked deeper", function () {
                var combined = combo.combine({
                    rewriteImports: true,
                    webRoot : COMPLEX_ROOT,
                    rootPath: COMPLEX_ROOT + '/deep-link/'
                });

                it("should read rootPath from filesystem directly", function (done) {
                    app.get("/c/:version/fs-deeper", combined, function (req, res, next) {
                        var rootPath = res.locals.rootPath;
                        rootPath.should.equal(path.join(COMPLEX_ROOT, '/versioned/deeper/base/'));

                        var relativePath = res.locals.relativePaths[0];
                        relativePath.should.equal('js/a.js');

                        next();
                    }, combo.respond);

                    assertRequestSuccess("/c/cafebabe/fs-deeper?js/a.js&js/b.js", done);
                });

                it("should *still* rewrite url() through symlink", function (done) {
                    app.get("/c/:version/ln-deeper", combined, function (req, res, next) {
                        var rootPath = res.locals.rootPath;
                        rootPath.should.equal(path.join(COMPLEX_ROOT, '/versioned/deeper/base/'));

                        var relativePath = res.locals.relativePaths[0];
                        relativePath.should.equal('css/urls/simple.css');

                        // console.error(res.body);
                        var expected = TEMPLATE_SIMPLE
                                        .replace(/__ROOT__/g, '/versioned/deeper/base/');
                        res.body.should.equal(expected);

                        next();
                    }, combo.respond);

                    assertRequestSuccess("/c/cafebabe/ln-deeper?css/urls/simple.css", done);
                });
            });
        });
    });
});
