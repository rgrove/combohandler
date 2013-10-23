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

var FIXTURES_DIR = __dirname + '/fixtures';

describe('combohandler', function () {
    /*jshint expr:true */

    var app, httpServer;

    before(function (done) {
        app = server({
            roots: {
                '/css': FIXTURES_DIR + '/root/css',
                '/js' : FIXTURES_DIR + '/root/js'
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
                rootPath: FIXTURES_DIR + '/root/js',
                maxAge  : null
            }), combo.respond);

            app.get('/max-age-0', combo.combine({
                rootPath: FIXTURES_DIR + '/root/js',
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
                var callbacks = combo.combine({ rootPath: FIXTURES_DIR + '/:root/js' });
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
                rootPath: FIXTURES_DIR + '/root/js'
            }), combo.respond);

            app.get('/error-throw?', combo.combine({
                rootPath: FIXTURES_DIR + '/root/js'
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

        it('should set content-type text/plain when responding 400 Bad Request', function (done) {
            request(BASE_URL + '/js?bogus.js', function (err, res, body) {
                assert.ifError(err);
                res.should.have.status(400);
                res.should.have.header('content-type', 'text/plain; charset=utf-8');
                done();
            });
        });

        it('should return a 500 when error before middleware', assertResponds({
            path: '/error-next?a.js',
            status: 500
        }));

        it('should return a 500 when error after middleware', assertResponds({
            path: '/error-throw?a.js',
            status: 500
        }));

        it('should return a 400 Bad Request error when no files are specified', assertResponds({
            path: '/js',
            body: 'Bad request. No files requested.',
            status: 400
        }));

        it('should throw a 400 Bad Request error when a file is not found', assertResponds({
            path: '/js?bogus.js',
            body: 'Bad request. File not found: bogus.js',
            status: 400
        }));

        it('should throw a 400 Bad Request error when a white-listed MIME type is not found', assertResponds({
            path: '/js?foo.bar',
            body: 'Bad request. Illegal MIME type present.',
            status: 400
        }));

        it('should throw a 400 Bad Request error when an unmapped MIME type is found with other valid types', assertResponds({
            path: '/js?a.js&foo.bar',
            body: 'Bad request. Only one MIME type allowed per request.',
            status: 400
        }));

        it('should throw a 400 Bad Request error when more than one valid MIME type is found', assertResponds({
            path: '/js?a.js&b.css',
            body: 'Bad request. Only one MIME type allowed per request.',
            status: 400
        }));

        it('should throw a 400 Bad Request error when a querystring is truncated', assertResponds({
            path: '/js?a.js&b',
            body: 'Bad request. Truncated query parameters.',
            status: 400
        }));

        it('should throw a 400 Bad Request error when a querystring is dramatically truncated', assertResponds({
            path: '/js?a',
            body: 'Bad request. Truncated query parameters.',
            status: 400
        }));

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
                        body.should.match(/^Bad request. File not found: /);
                        done();
                    });
                });
            });
        });
    });

    // -- Optional Middleware --------------------------------------------------
    describe("url rewrites", function () {
        // NOTE: we do not currently support the space terminator for CSS escapes.
        // ".unicode-escaped { background: url(__PATH__d\\E9 cha\\EEn\\E9.png); }",
        var TEMPLATE_URLS = fs.readFileSync(path.join(FIXTURES_DIR, 'rewrite/urls.tmpl'), 'utf-8');
        var TEMPLATE_MORE = fs.readFileSync(path.join(FIXTURES_DIR, 'rewrite/deeper/more.tmpl'), 'utf-8');
        // TODO: are "../" paths being rewritten correctly?
        var TEMPLATE_IMPORTS = fs.readFileSync(path.join(FIXTURES_DIR, 'rewrite/imports.tmpl'), 'utf-8');

        var URLS_UNMODIFIED = fs.readFileSync(path.join(FIXTURES_DIR, 'rewrite/urls.css'), 'utf-8');
        var IMPORTS_UNMODIFIED = fs.readFileSync(path.join(FIXTURES_DIR, 'rewrite/imports.css'), 'utf-8');

        before(function () {
            app.get('/norewrite', combo.combine({
                rootPath: FIXTURES_DIR + '/rewrite'
            }), combo.respond);

            app.get('/rewrite', combo.combine({
                rootPath: FIXTURES_DIR + '/rewrite',
                basePath: "/rewritten/"
            }), combo.respond);

            app.get('/rewrite-noslash', combo.combine({
                rootPath: FIXTURES_DIR + '/rewrite',
                basePath: "/rewritten"
            }), combo.respond);

            app.get('/rewrite-imports', combo.combine({
                rootPath: FIXTURES_DIR + '/rewrite',
                basePath: "/rewritten/",
                rewriteImports: true
            }), combo.respond);

            app.get('/rewrite-middleware-before-combine',
                combo.cssUrls({ basePath: "/rewritten/" }),
                combo.combine({ rootPath: FIXTURES_DIR + '/rewrite' }),
            combo.respond);

            app.get('/rewrite-middleware-noconfig',
                combo.combine({ rootPath: FIXTURES_DIR + '/rewrite' }),
                combo.cssUrls(),
            combo.respond);

            app.get('/rewrite-root', combo.combine({
                rootPath: FIXTURES_DIR + '/rewrite',
                webRoot:  FIXTURES_DIR + '/'
            }), combo.respond);

            app.get('/rewrite-root-noslash', combo.combine({
                rootPath: FIXTURES_DIR + '/rewrite',
                webRoot:  FIXTURES_DIR
            }), combo.respond);

            app.get('/rewrite-root-imports', combo.combine({
                rootPath: FIXTURES_DIR + '/rewrite',
                webRoot:  FIXTURES_DIR + '/',
                rewriteImports: true
            }), combo.respond);
        });

        it("should not rewrite without a basePath or webRoot", assertResponds({
            path: "/norewrite?urls.css",
            body: URLS_UNMODIFIED
        }));

        it("should not rewrite without a basePath or webRoot as middleware", assertResponds({
            path: "/rewrite-middleware-noconfig?urls.css",
            body: URLS_UNMODIFIED
        }));

        it("should not rewrite when middleware before combine()", assertResponds({
            path: "/rewrite-middleware-before-combine?urls.css",
            body: URLS_UNMODIFIED
        }));

        describe("with configured basePath", function () {
            var URLS_REWRITTEN = TEMPLATE_URLS.replace(/__PATH__/g, '/rewritten/');
            var MORE_REWRITTEN = TEMPLATE_MORE.replace(/__PATH__/g, '/rewritten/');

            var MORE_URLS_REWRITTEN = [URLS_REWRITTEN, MORE_REWRITTEN].join("\n");

            var IMPORTS_REWRITTEN = TEMPLATE_IMPORTS.replace(/__PATH__/g, '/rewritten/')
                                                    .replace(/__DOTS__/g, '');

            it("should allow basePath without trailing slash", assertResponds({
                path: "/rewrite-noslash?urls.css",
                body: URLS_REWRITTEN
            }));

            it("should rewrite valid urls", assertResponds({
                path: "/rewrite?urls.css&deeper/more.css",
                body: MORE_URLS_REWRITTEN
            }));

            it("should NOT rewrite import paths when disabled", assertResponds({
                path: "/rewrite?imports.css",
                body: IMPORTS_UNMODIFIED
            }));

            it("should rewrite import paths when enabled", assertResponds({
                path: "/rewrite-imports?imports.css",
                body: IMPORTS_REWRITTEN
            }));
        });

        describe("with configured webRoot", function () {
            var URLS_REBASED = TEMPLATE_URLS.replace(/__PATH__/g, '/rewrite/');
            var MORE_REBASED = TEMPLATE_MORE.replace(/__PATH__/g, '/rewrite/');

            var MORE_URLS_REBASED = [URLS_REBASED, MORE_REBASED].join("\n");

            var IMPORTS_REBASED = TEMPLATE_IMPORTS.replace(/__PATH__/g, '/rewrite/')
                                                  .replace(/__DOTS__/g, '');

            it("should allow webRoot without trailing slash", assertResponds({
                path: "/rewrite-root-noslash?urls.css",
                body: URLS_REBASED
            }));

            it("should rewrite valid urls", assertResponds({
                path: "/rewrite-root?urls.css&deeper/more.css",
                body: MORE_URLS_REBASED
            }));

            it("should NOT rewrite import paths when disabled", assertResponds({
                path: "/rewrite-root?imports.css",
                body: IMPORTS_UNMODIFIED
            }));

            it("should rewrite import paths when enabled", assertResponds({
                path: "/rewrite-root-imports?imports.css",
                body: IMPORTS_REBASED
            }));
        });
    });

    describe("dynamic paths", function () {
        before(function () {
            app.get('/dynamic/:version',
                combo.combine({ rootPath: FIXTURES_DIR + '/dynamic/:version' }),
            combo.respond);

            app.get('/:version/param-first',
                combo.combine({ rootPath: FIXTURES_DIR + '/dynamic/:version' }),
            combo.respond);

            app.get('/dynamic/:version/empty-combo',
                combo.dynamicPath({ rootPath: FIXTURES_DIR + '/dynamic/:version/static' }),
                combo.combine(),
            combo.respond);

            app.get('/dynamic/:version/doubled',
                combo.dynamicPath({ rootPath: FIXTURES_DIR + '/dynamic/:version/static' }),
                combo.combine({     rootPath: FIXTURES_DIR + '/dynamic/:version/static' }),
            combo.respond);

            app.get('/non-dynamic',
                combo.dynamicPath({ rootPath: FIXTURES_DIR + '/dynamic/decafbad' }),
                combo.combine({     rootPath: FIXTURES_DIR + '/dynamic/decafbad' }),
            combo.respond);

            app.get('/dynamic-no-config',
                combo.dynamicPath(),
                combo.combine({     rootPath: FIXTURES_DIR + '/dynamic/decafbad' }),
            combo.respond);

            app.get('/route-only/:version/lib',
                combo.combine({ rootPath: FIXTURES_DIR + '/root' }),
            combo.respond);
        });

        it("should work when param found at end of path", assertResponds({
            path: "/dynamic/decafbad?a.js&b.js",
            body: "a();\n\nb();\n"
        }));

        it("should work when param found at beginning of path", assertResponds({
            path: "/decafbad/param-first?a.js&static/c.js",
            body: "a();\n\nc();\n"
        }));

        it("should work when rootPath not passed to combine()", assertResponds({
            path: "/dynamic/decafbad/empty-combo?c.js&d.js",
            body: "c();\n\nd();\n"
        }));

        it("should work when param found before end of path", assertResponds({
            path: "/dynamic/decafbad/empty-combo?c.js&d.js",
            body: "c();\n\nd();\n"
        }));

        it("should work when middleware is run twice on same route", assertResponds({
            path: "/dynamic/decafbad/doubled?c.js&d.js",
            body: "c();\n\nd();\n"
        }));

        it("should not fail when param not present", assertResponds({
            path: "/non-dynamic?a.js&b.js",
            body: "a();\n\nb();\n"
        }));

        it("should not fail when config missing", assertResponds({
            path: "/dynamic-no-config?a.js&b.js",
            body: "a();\n\nb();\n"
        }));

        it("should work when param only found in route, not rootPath", assertResponds({
            path: "/route-only/deadbeef/lib?js/a.js&js/b.js",
            body: "a();\n\nb();\n"
        }));

        it("should error when param does not correspond to existing path", assertResponds({
            path: "/dynamic/deadbeef?a.js",
            body: "Bad request. Unable to resolve path: /dynamic/deadbeef",
            status: 400
        }));

        describe("with multiple parameters", function () {
            before(function () {
                app.get("/dynamic/:major/:minor",
                    combo.combine({ rootPath: FIXTURES_DIR + "/dynamic/:major/:minor" }),
                combo.respond);

                app.get("/:major/:minor/rootpath-omit",
                    combo.combine({ rootPath: FIXTURES_DIR + "/dynamic/:major/static" }),
                combo.respond);

                app.get("/omit-route/:major",
                    combo.combine({ rootPath: FIXTURES_DIR + "/dynamic/:major/:minor" }),
                combo.respond);

                app.get("/:major/separated/route/:minor",
                    combo.combine({ rootPath: FIXTURES_DIR + "/:major/:minor/static" }),
                combo.respond);

                app.get("/:major/separated/path/:minor",
                    combo.combine({ rootPath: FIXTURES_DIR + "/:major/decafbad/:minor" }),
                combo.respond);

                app.get('/doubled-in-rootpath/:major',
                    combo.combine({ rootPath: FIXTURES_DIR + '/dynamic/:major/:major' }),
                combo.respond);

                app.get('/doubled-with-suffixes/:major',
                    combo.combine({ rootPath: FIXTURES_DIR + '/dynamic/:major/static/:major' }),
                combo.respond);
            });

            it("should resolve path", assertResponds({
                path: "/dynamic/decafbad/static?c.js&d.js",
                body: "c();\n\nd();\n"
            }));

            it("should resolve root path that omits route parameter", assertResponds({
                path: "/decafbad/latest/rootpath-omit?c.js&d.js",
                body: "c();\n\nd();\n"
            }));

            it("should resolve route that has more parameters than root path", assertResponds({
                path: "/omit-route/decafbad?a.js&static/c.js",
                body: "a();\n\nc();\n"
            }));

            it("should resolve route that has separated parameters", assertResponds({
                path: "/dynamic/separated/route/decafbad?c.js&d.js",
                body: "c();\n\nd();\n"
            }));

            it("should resolve root path that has separated parameters", assertResponds({
                path: "/dynamic/separated/path/static?c.js&d.js",
                body: "c();\n\nd();\n"
            }));

            it("should resolve route that has identical parameters in root path", assertResponds({
                path: "/doubled-in-rootpath/baddecaf?e.js&f.js",
                body: "e();\n\nf();\n"
            }));

            it("should resolve route that has separated identical parameters in root path", assertResponds({
                path: "/doubled-with-suffixes/cafebabe?g.js&h.js",
                body: "g();\n\nh();\n"
            }));
        });
    });

    // -- Complex Integration --------------------------------------------------
    describe("complex", function () {
        // Strange things may happen when you mix symlinks, parameters, and complex routes
        var COMPLEX_ROOT = FIXTURES_DIR + '/complex';

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

        function dynamicFiletree(opts) {
            var expectedRelativePath = opts.relativePath || "js/a.js";
            var expectedResolvedPath = path.join(COMPLEX_ROOT, opts.realPath, expectedRelativePath);
            var expectedRootPath     = path.join(COMPLEX_ROOT, opts.rootPath);

            return function (req, res, next) {
                var rootPath = res.locals.rootPath;
                rootPath.should.equal(expectedRootPath);

                var relativePath = res.locals.relativePaths[0];
                relativePath.should.equal(expectedRelativePath);

                fs.realpath(path.join(rootPath, relativePath), function (err, resolved) {
                    assert.ifError(err);
                    resolved.should.equal(expectedResolvedPath);
                    next();
                });
            };
        }

        function dynamicSymlinks(opts) {
            var expectedTemplateFile = opts.template || TEMPLATE_SIMPLE;
            var expectedRelativePath = opts.relativePath || "css/urls/simple.css";
            var expectedResolvedBody = expectedTemplateFile.replace(/__ROOT__/g, opts.rootPath);

            return function (req, res, next) {
                var relativePath = res.locals.relativePaths[0];
                relativePath.should.equal(expectedRelativePath);

                // console.error(res.body);
                res.body.should.equal(expectedResolvedBody);

                next();
            };
        }

        describe("route with fully-qualified dynamic path", function () {
            before(function () {
                var combined = combo.combine({
                    webRoot : COMPLEX_ROOT,
                    rootPath: COMPLEX_ROOT + '/versioned/:version/base/'
                });

                app.get("/c/:version/fs-fq", combined, dynamicFiletree({
                    realPath: "/versioned/deeper/base/",
                    rootPath: "/versioned/deeper/base/"
                }), combo.respond);

                app.get("/c/:version/ln-fq", combined, dynamicFiletree({
                    realPath: "/base/",
                    rootPath: "/versioned/shallower/base/"
                }), combo.respond);

                app.get("/c/:version/fq-noimports", combined, dynamicSymlinks({
                    template: SIMPLE_IMPORTS_RAW + TEMPLATE_URLS_SIMPLE,
                    realPath: "/versioned/shallower/base/",
                    rootPath: "/versioned/shallower/base/"
                }), combo.respond);
            });

            it("should read rootPath from filesystem directly", assertResponds({
                path: "/c/deeper/fs-fq?js/a.js&js/b.js"
            }));

            it("should resolve rootPath through symlink", assertResponds({
                path: "/c/shallower/ln-fq?js/a.js&js/b.js"
            }));

            it("should only rewrite url() through symlink, not imports", assertResponds({
                path: "/c/shallower/fq-noimports?css/urls/simple.css"
            }));
        });

        describe("route with one-sided dynamic path", function () {
            describe("and rootPath symlinked shallower", function () {
                describe("when resolveSymlinks is true", function () {
                    before(function () {
                        var resolved = combo.combine({
                            rewriteImports: true,
                            webRoot : COMPLEX_ROOT,
                            rootPath: COMPLEX_ROOT + '/versioned/shallower/base/'
                        });

                        app.get("/r/:version/fs-shallow", resolved, dynamicFiletree({
                            realPath: "/base/",
                            rootPath: "/base/"
                        }), combo.respond);

                        app.get("/r/:version/ln-shallow", resolved, dynamicSymlinks({
                            rootPath: "/base/"
                        }), combo.respond);
                    });

                    it("should resolve files from realpath in filesystem", assertResponds({
                        path: "/r/cafebabe/fs-shallow?js/a.js&js/b.js"
                    }));

                    it("should rewrite url() through symlink", assertResponds({
                        path: "/r/cafebabe/ln-shallow?css/urls/simple.css"
                    }));
                });

                describe("when resolveSymlinks is false", function () {
                    before(function () {
                        var symlinkd = combo.combine({
                            rewriteImports: true,
                            resolveSymlinks: false,
                            webRoot : COMPLEX_ROOT,
                            rootPath: COMPLEX_ROOT + '/versioned/shallower/base/'
                        });

                        app.get("/s/:version/fs-shallow", symlinkd, dynamicFiletree({
                            realPath: "/base/",
                            rootPath: "/versioned/shallower/base/"
                        }), combo.respond);

                        app.get("/s/:version/ln-shallow", symlinkd, dynamicSymlinks({
                            rootPath: "/versioned/shallower/base/"
                        }), combo.respond);
                    });

                    it("should resolve files from symlink in filesystem", assertResponds({
                        path: "/s/cafebabe/fs-shallow?js/a.js&js/b.js"
                    }));

                    it("should rewrite url() using symlink", assertResponds({
                        path: "/s/cafebabe/ln-shallow?css/urls/simple.css"
                    }));
                });
            });

            describe("and rootPath symlinked deeper", function () {
                describe("when resolveSymlinks is true", function () {
                    before(function () {
                        var resolved = combo.combine({
                            rewriteImports: true,
                            webRoot : COMPLEX_ROOT,
                            rootPath: COMPLEX_ROOT + '/deep-link/'
                        });

                        app.get("/r/:version/fs-deeper", resolved, dynamicFiletree({
                            realPath: "/versioned/deeper/base/",
                            rootPath: "/versioned/deeper/base/"
                        }), combo.respond);

                        app.get("/r/:version/ln-deeper", resolved, dynamicSymlinks({
                            rootPath: "/versioned/deeper/base/"
                        }), combo.respond);
                    });

                    it("should read rootPath from filesystem directly", assertResponds({
                        path: "/r/cafebabe/fs-deeper?js/a.js&js/b.js"
                    }));

                    it("should *still* rewrite url() through symlink", assertResponds({
                        path: "/r/cafebabe/ln-deeper?css/urls/simple.css"
                    }));
                });

                describe("when resolveSymlinks is false", function () {
                    before(function () {
                        var symlinkd = combo.combine({
                            rewriteImports: true,
                            resolveSymlinks: false,
                            webRoot : COMPLEX_ROOT,
                            rootPath: COMPLEX_ROOT + '/deep-link/'
                        });

                        app.get("/s/:version/fs-deeper", symlinkd, dynamicFiletree({
                            realPath: "/versioned/deeper/base/",
                            rootPath: "/deep-link/"
                        }), combo.respond);

                        app.get("/s/:version/ln-deeper", symlinkd, dynamicSymlinks({
                            rootPath: "/deep-link/"
                        }), combo.respond);
                    });

                    it("should read rootPath from symlink in filesystem", assertResponds({
                        path: "/s/cafebabe/fs-deeper?js/a.js&js/b.js"
                    }));

                    it("should *still* rewrite url() using symlink", assertResponds({
                        path: "/s/cafebabe/ln-deeper?css/urls/simple.css"
                    }));
                });
            });
        });
    });

    // -- Helpers --------------------------------------------------------------
    function assertResponds(config) {
        var expectedPath = config.path;
        var expectedBody = config.body;
        var expectedStatus = config.status || 200;

        return function (done) {
            request(BASE_URL + config.path, function (err, res, body) {
                assert.ifError(err);
                if (expectedBody) {
                    body.should.equal(expectedBody);
                }
                res.should.have.status(expectedStatus);
                done();
            });
        };
    }
});
