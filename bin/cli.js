#!/usr/bin/env node

var options = require('../lib/args').parse();

if (options.cluster) {
    // Cluster constructor calls #listen() if no other action
    require('../lib/cluster')(options);
} else {
    // Legacy support
    var instance = require('../lib/server')(options);
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
//      ./bin/cli.js --cluster -f ./test/root.json
//
//  Browser:
//      localhost:8000/test?js/a.js&js/b.js
//      localhost:8000/test?css/a.css&css/b.css
