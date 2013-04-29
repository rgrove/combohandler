#!/usr/bin/env node

var args = require('../lib/args');
var options = args.parse();
var instance;

if (options.version) {
    console.log('v' + args.version);
    process.exit(0);
} else if (options.help) {
    console.error(args.usage);
    process.exit(0);
}

if (options.cluster) {
    // Cluster support
    instance = require('../lib/cluster')(options);

    args.invoke(instance);
} else {
    // Legacy support
    instance = require('../lib/server')(options);
    var port = options.port || require('../lib/defaults').master.port;

    if (!options.quiet) {
        console.log("combohandler: Listening on http://localhost:%d/", port);
        console.log("Press Ctrl+C to exit.");
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
