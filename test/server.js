/*global describe, before, after, it */
var combo   = require('../'),
    server  = require('../lib/server'),

    assert  = require('assert'),
    request = require('request'),

    PORT     = 8942,
    BASE_URL = 'http://localhost:' + PORT;

process.env['NODE_ENV'] = 'test';

describe('combohandler', function () {
    var app, httpServer;

    before(function () {
        app = server({
            roots: {
                '/css': __dirname + '/fixtures/root/css',
                '/js' : __dirname + '/fixtures/root/js'
            }
        });

        httpServer = app.listen(PORT);
    });

    after(function () {
        httpServer.close();
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

                var expires = new Date(res.headers['expires']);
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

                var expires = new Date(res.headers['expires']);
                ((expires - Date.now()) / 1000).should.be.within(-5, 5);

                done();
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

    // -- URL Rewrites ---------------------------------------------------------
    describe("url rewrites", function () {
        before(function () {
            app.get('/norewrite', combo.combine({
                rootPath: __dirname + '/fixtures/rewrite'
            }), combo.respond);

            app.get('/rewrite', combo.combine({
                rootPath: __dirname + '/fixtures/rewrite',
                basePath: "/rewritten"
            }), combo.respond);

            app.get('/rewrite-noslash', combo.combine({
                rootPath: __dirname + '/fixtures/rewrite',
                basePath: "/rewritten/"
            }), combo.respond);

            app.get('/rewrite-imports', combo.combine({
                rootPath: __dirname + '/fixtures/rewrite',
                basePath: "/rewritten/",
                rewriteImports: true
            }), combo.respond);
        });

        it("should allow the basePath to end in a slash", function (done) {
            request(BASE_URL + "/rewrite-noslash?urls.css", function (err, res, body) {
                assert.ifError(err);
                body.should.equal([
                    "#no-quotes { background: url(/rewritten/no-quotes.png);}",
                    "#single-quotes { background: url(\'/rewritten/single-quotes.png\');}",
                    "#double-quotes { background: url(\"/rewritten/double-quotes.png\");}",
                    "#spaces { background: url(",
                    "  \"/rewritten/spaces.png\" );}",
                    "#data-url { background: url(data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==);}",
                    "#absolute-url { background: url(http://www.example.com/foo.gif?a=b&c=d#bebimbop);}",
                    "#protocol-relative-url { background: url(//www.example.com/foo.gif?a=b&c=d#bebimbop);}",
                    "#escaped-stuff { background:url(\"/rewritten/\\)\\\";\\'\\(.png\"); }",
                    ".unicode-raw { background: url(/rewritten/déchaîné.png); }",
                    ".unicode-escaped { background: url(/rewritten/d\\0000E9cha\\EEn\\E9.png); }",
                    ".nl-craziness { background:",
                    "    url(/rewritten/crazy.png",
                    "    ); }",
                    ""
                ].join("\n"));
                done();
            });
        });

        it("should not rewrite without a basePath", function (done) {
            request(BASE_URL + "/norewrite?urls.css", function (err, res, body) {
                assert.ifError(err);
                body.should.equal([
                    "#no-quotes { background: url(no-quotes.png);}",
                    "#single-quotes { background: url(\'single-quotes.png\');}",
                    "#double-quotes { background: url(\"double-quotes.png\");}",
                    "#spaces { background: url(",
                    "  \"spaces.png\" );}",
                    "#data-url { background: url(data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==);}",
                    "#absolute-url { background: url(http://www.example.com/foo.gif?a=b&c=d#bebimbop);}",
                    "#protocol-relative-url { background: url(//www.example.com/foo.gif?a=b&c=d#bebimbop);}",
                    "#escaped-stuff { background:url(\"\\)\\\";\\'\\(.png\"); }",
                    ".unicode-raw { background: url(déchaîné.png); }",
                    ".unicode-escaped { background: url(d\\0000E9cha\\EEn\\E9.png); }",
                    ".nl-craziness { background:",
                    "    url(crazy.png",
                    "    ); }",
                    ""
                ].join("\n"));
                done();
            });
        });

        it("should rewrite valid urls", function (done) {
            request(BASE_URL + "/rewrite?urls.css&deeper/more.css", function (err, res, body) {
                assert.ifError(err);
                body.should.equal([
                    "#no-quotes { background: url(/rewritten/no-quotes.png);}",
                    "#single-quotes { background: url(\'/rewritten/single-quotes.png\');}",
                    "#double-quotes { background: url(\"/rewritten/double-quotes.png\");}",
                    "#spaces { background: url(",
                    "  \"/rewritten/spaces.png\" );}",
                    "#data-url { background: url(data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==);}",
                    "#absolute-url { background: url(http://www.example.com/foo.gif?a=b&c=d#bebimbop);}",
                    "#protocol-relative-url { background: url(//www.example.com/foo.gif?a=b&c=d#bebimbop);}",
                    "#escaped-stuff { background:url(\"/rewritten/\\)\\\";\\'\\(.png\"); }",
                    ".unicode-raw { background: url(/rewritten/déchaîné.png); }",
                    // NOTE: we do not currently support the space terminator for CSS escapes.
                    // ".unicode-escaped { background: url(/rewritten/d\\E9 cha\\EEn\\E9.png); }",
                    ".unicode-escaped { background: url(/rewritten/d\\0000E9cha\\EEn\\E9.png); }",
                    ".nl-craziness { background:",
                    "    url(/rewritten/crazy.png",
                    "    ); }",
                    "",
                    "#depth { background: url(/rewritten/deeper/deeper.png);}",
                    "#up-one { background: url(/rewritten/shallower.png);}",
                    "#down-one { background: url(/rewritten/deeper/more/down-one.png);}"
                ].join("\n"));
                done();
            });
        });

        it("should rewrite import paths when enabled from combine", function (done) {
            request(BASE_URL + "/rewrite-imports?imports.css", function (err, res, body) {
                assert.ifError(err);
                body.should.equal([
                    "@import '/rewritten/basic-sq.css';",
                    "@import \"/rewritten/basic-dq.css\";",
                    "@import url(/rewritten/url-uq.css);",
                    "@import url('/rewritten/url-sq.css');",
                    "@import url(\"/rewritten/url-dq.css\");",
                    "@import \"/rewritten/media-simple.css\" print;",
                    "@import url(\"/rewritten/media-simple-url.css\") print;",
                    "@import '/rewritten/media-simple-comma.css' print, screen;",
                    "@import \"/rewritten/media-complex.css\" screen and (min-width: 400px) and (max-width: 700px);",
                    "@import url(\"/rewritten/media-complex-url.css\") screen and (min-width: 400px) and (max-width: 700px);",
                    // TODO: are the following rewritten correctly?
                    "@import \"/rewrite/deeper/more.css\";",
                    "@import \"/root/css/a.css\" (device-width: 320px);",
                    ""
                ].join("\n"));
                done();
            });
        });

        describe("as middleware", function () {
            before(function () {
                app.get('/rewrite-middleware-ignore',
                    combo.combine({ rootPath: __dirname + '/fixtures/root/js' }),
                    combo.cssUrls({ basePath: "/rewritten/" }),
                combo.respond);

                app.get('/rewrite-middleware',
                    combo.combine({ rootPath: __dirname + '/fixtures/rewrite' }),
                    combo.cssUrls({ basePath: "/rewritten/" }),
                combo.respond);

                app.get('/rewrite-middleware-imports',
                    combo.combine({ rootPath: __dirname + '/fixtures/rewrite' }),
                    combo.cssUrls({ basePath: "/rewritten/", rewriteImports: true }),
                combo.respond);
            });

            it("should avoid modifying non-CSS requests", function (done) {
                request(BASE_URL + '/rewrite-middleware-ignore?a.js&b.js', function (err, res, body) {
                    assert.ifError(err);
                    res.should.have.status(200);
                    res.should.have.header('content-type', 'application/javascript; charset=utf-8');
                    res.should.have.header('last-modified');
                    body.should.equal('a();\n\nb();\n');
                    done();
                });
            });

            it("should rewrite valid urls", function (done) {
                request(BASE_URL + "/rewrite-middleware?urls.css&deeper/more.css", function (err, res, body) {
                    assert.ifError(err);
                    body.should.equal([
                        "#no-quotes { background: url(/rewritten/no-quotes.png);}",
                        "#single-quotes { background: url(\'/rewritten/single-quotes.png\');}",
                        "#double-quotes { background: url(\"/rewritten/double-quotes.png\");}",
                        "#spaces { background: url(",
                        "  \"/rewritten/spaces.png\" );}",
                        "#data-url { background: url(data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==);}",
                        "#absolute-url { background: url(http://www.example.com/foo.gif?a=b&c=d#bebimbop);}",
                        "#protocol-relative-url { background: url(//www.example.com/foo.gif?a=b&c=d#bebimbop);}",
                        "#escaped-stuff { background:url(\"/rewritten/\\)\\\";\\'\\(.png\"); }",
                        ".unicode-raw { background: url(/rewritten/déchaîné.png); }",
                        ".unicode-escaped { background: url(/rewritten/d\\0000E9cha\\EEn\\E9.png); }",
                        ".nl-craziness { background:",
                        "    url(/rewritten/crazy.png",
                        "    ); }",
                        "",
                        "#depth { background: url(/rewritten/deeper/deeper.png);}",
                        "#up-one { background: url(/rewritten/shallower.png);}",
                        "#down-one { background: url(/rewritten/deeper/more/down-one.png);}"
                    ].join("\n"));
                    done();
                });
            });

            it("should NOT rewrite import paths when disabled", function (done) {
                request(BASE_URL + "/rewrite-middleware?imports.css", function (err, res, body) {
                    assert.ifError(err);
                    body.should.equal([
                        "@import 'basic-sq.css';",
                        "@import \"basic-dq.css\";",
                        "@import url(url-uq.css);",
                        "@import url('url-sq.css');",
                        "@import url(\"url-dq.css\");",
                        "@import \"media-simple.css\" print;",
                        "@import url(\"media-simple-url.css\") print;",
                        "@import 'media-simple-comma.css' print, screen;",
                        "@import \"media-complex.css\" screen and (min-width: 400px) and (max-width: 700px);",
                        "@import url(\"media-complex-url.css\") screen and (min-width: 400px) and (max-width: 700px);",
                        "@import \"../rewrite/deeper/more.css\";",
                        "@import \"../root/css/a.css\" (device-width: 320px);",
                        ""
                    ].join("\n"));
                    done();
                });
            });

            it("should rewrite import paths when enabled", function (done) {
                request(BASE_URL + "/rewrite-middleware-imports?imports.css", function (err, res, body) {
                    assert.ifError(err);
                    body.should.equal([
                        "@import '/rewritten/basic-sq.css';",
                        "@import \"/rewritten/basic-dq.css\";",
                        "@import url(/rewritten/url-uq.css);",
                        "@import url('/rewritten/url-sq.css');",
                        "@import url(\"/rewritten/url-dq.css\");",
                        "@import \"/rewritten/media-simple.css\" print;",
                        "@import url(\"/rewritten/media-simple-url.css\") print;",
                        "@import '/rewritten/media-simple-comma.css' print, screen;",
                        "@import \"/rewritten/media-complex.css\" screen and (min-width: 400px) and (max-width: 700px);",
                        "@import url(\"/rewritten/media-complex-url.css\") screen and (min-width: 400px) and (max-width: 700px);",
                        // TODO: are the following rewritten correctly?
                        "@import \"/rewrite/deeper/more.css\";",
                        "@import \"/root/css/a.css\" (device-width: 320px);",
                        ""
                    ].join("\n"));
                    done();
                });
            });
        });
    });

    // Dynamic Paths ----------------------------------------------------------
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

        it("should error when param does not correspond to existing path", function (done) {
            request(BASE_URL + '/dynamic/deadbeef?a.js', function (err, res, body) {
                assert.ifError(err);
                res.should.have.status(400);
                body.should.equal('Bad request. Unable to resolve path: /dynamic/deadbeef');
                done();
            });
        });
    });
});
