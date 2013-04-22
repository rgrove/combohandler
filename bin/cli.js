#!/usr/bin/env node

var args = require('../lib/args');
var options = args.parse();
var instance;

if (options.version) {
    console.log('v' + args.version);
    process.exit(0);
}

if (options.cluster) {
    // Cluster support
    instance = require('../lib/cluster')(options);

    if (options.restart) {
        instance.restart();
    }
    else if (options.shutdown) {
        instance.shutdown();
    }
    else if (options.status) {
        instance.status();
    }
    else if (options.stop) {
        instance.stop();
    }
    else {
        instance.listen();
    }
} else {
    // Legacy support
    instance = require('../lib/server')(options);
    var port = options.port || require('../lib/defaults').master.port;

    if (!options.quiet) {
        console.log("combohandler: Listening on http://localhost:%d/", port);
    }

    instance.listen(port);
}


//  Local "integration" test from root of combohandler repo
//
//  Terminal:
//      ./bin/cli.js -f ./test/root.json
//      ./bin/cli.js -f ./test/root.json --cluster
//
//  Browser:
//      localhost:8000/js?a.js&b.js
//      localhost:8000/css?a.css&b.css
