var server  = require('../lib/server'),

    assert  = require('assert'),
    express = require('express'),
    request = require('request'),

    PORT     = 8942,
    BASE_URL = 'http://localhost:' + PORT;

process.env['NODE_ENV'] = 'test';

describe('combohandler', function () {
    var app;

    before(function () {
        app = server({
            roots: {
                '/css': __dirname + '/fixtures/css',
                '/js' : __dirname + '/fixtures/js'
            }
        });

        app.listen(PORT);
    });

    after(function () {
        app.close();
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

    it('should return a 400 Bad Request error when no files are specified', function (done) {
        request(BASE_URL + '/js', function (err, res, body) {
            assert.equal(err, null);
            res.should.have.status(400);
            body.should.equal('Bad request.');
            done();
        });
    });


    it('should throw a 400 Bad Request error when a file is not found', function (done) {
        request(BASE_URL + '/js?bogus.js', function (err, res, body) {
            assert.equal(err, null);
            res.should.have.status(400);
            res.should.have.header('content-type', 'text/plain; charset=utf-8');
            body.should.equal('Bad request.');
            done();
        });
    });

    it('should throw a 400 Bad Request error when directory traversal is attempted', function (done) {
        request(BASE_URL + '/js?../../../package.json', function (err, res, body) {
            assert.equal(err, null);
            res.should.have.status(400);
            res.should.have.header('content-type', 'text/plain; charset=utf-8');
            body.should.equal('Bad request.');
            done();
        });
    });
});
