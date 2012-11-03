var combo   = require('../'),
    server  = require('../lib/server'),

    assert  = require('assert'),
    express = require('express'),
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
            assert.equal(err, null);
            res.should.have.status(200);
            res.should.have.header('content-type', 'application/javascript;charset=utf-8');
            res.should.have.header('last-modified');
            body.should.equal('a();\n\nb();\n');
            done();
        });
    });

    it('should combine CSS', function (done) {
        request(BASE_URL + '/css?a.css&b.css', function (err, res, body) {
            assert.equal(err, null);
            res.should.have.status(200);
            res.should.have.header('content-type', 'text/css;charset=utf-8');
            res.should.have.header('last-modified');
            body.should.equal('.a { color: green; }\n\n.b { color: green; }\n');
            done();
        });
    });

    it('should support symlinks pointing outside the root', function (done) {
        request(BASE_URL + '/js?a.js&b.js&outside.js', function (err, res, body) {
            assert.equal(err, null);
            res.should.have.status(200);
            res.should.have.header('content-type', 'application/javascript;charset=utf-8');
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
            }), function (req, res) {
                res.send(res.body, 200);
            });

            app.get('/max-age-0', combo.combine({
                rootPath: __dirname + '/fixtures/root/js',
                maxAge  : 0
            }), function (req, res) {
                res.send(res.body, 200);
            });
        });

        it('should default to one year', function (done) {
            request(BASE_URL + '/js?a.js', function (err, res, body) {
                assert.equal(err, null);
                res.should.have.status(200);
                res.should.have.header('cache-control', 'public,max-age=31536000');

                var expires = new Date(res.headers['expires']);
                ((expires - Date.now()) / 1000).should.be.within(31535990, 31536000);

                done();
            });
        });

        it('should not set Cache-Control and Expires headers when maxAge is null', function (done) {
            request(BASE_URL + '/max-age-null?a.js', function (err, res, body) {
                assert.equal(err, null);
                res.should.have.status(200);
                res.headers.should.not.have.property('cache-control');
                res.headers.should.not.have.property('expires');
                done();
            });
        });

        it('should support a maxAge of 0', function (done) {
            request(BASE_URL + '/max-age-0?a.js', function (err, res, body) {
                assert.equal(err, null);
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
        it('should return a 400 Bad Request error when no files are specified', function (done) {
            request(BASE_URL + '/js', function (err, res, body) {
                assert.equal(err, null);
                res.should.have.status(400);
                body.should.equal('Bad request. No files requested.');
                done();
            });
        });

        it('should throw a 400 Bad Request error when a file is not found', function (done) {
            request(BASE_URL + '/js?bogus.js', function (err, res, body) {
                assert.equal(err, null);
                res.should.have.status(400);
                res.should.have.header('content-type', 'text/plain; charset=utf-8');
                body.should.equal('Bad request. File not found: bogus.js');
                done();
            });
        });

        it('should throw a 400 Bad Request error when a white-listed MIME type is not found', function (done) {
            request(BASE_URL + '/js?foo.bar', function (err, res, body) {
                assert.equal(err, null);
                res.should.have.status(400);
                body.should.equal('Bad request. Illegal MIME type present.');
                done();
            });
        });

        it('should throw a 400 Bad Request error when an unmapped MIME type is found with other valid types', function (done) {
            request(BASE_URL + '/js?a.js&foo.bar', function (err, res, body) {
                assert.equal(err, null);
                res.should.have.status(400);
                body.should.equal('Bad request. Only one MIME type allowed per request.');
                done();
            });
        });

        it('should throw a 400 Bad Request error when more than one valid MIME type is found', function (done) {
            request(BASE_URL + '/js?a.js&b.css', function (err, res, body) {
                assert.equal(err, null);
                res.should.have.status(400);
                body.should.equal('Bad request. Only one MIME type allowed per request.');
                done();
            });
        });

        it('should throw a 400 Bad Request error when a querystring is truncated', function (done) {
            request(BASE_URL + '/js?a.js&b', function (err, res, body) {
                assert.equal(err, null);
                res.should.have.status(400);
                body.should.equal('Bad request. Truncated query parameters.');
                done();
            });
        });

        it('should throw a 400 Bad Request error when a querystring is dramatically truncated', function (done) {
            request(BASE_URL + '/js?a', function (err, res, body) {
                assert.equal(err, null);
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
                        assert.equal(err, null);
                        res.should.have.status(400);
                        res.should.have.header('content-type', 'text/plain; charset=utf-8');
                        body.should.match(/^Bad request. File not found: /);
                        done();
                    });
                });
            });
        });
    });
});
