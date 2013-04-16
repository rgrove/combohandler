#!/usr/bin/env node

var args = require('../lib/args'),
    comboCluster = require('../lib/cluster');

comboCluster(args.parse());

//  Local "integration" test from root of combohandler repo
//
//  Terminal:
//      ./bin/cli.js -f ./test/root.json
//
//  Browser:
//      localhost:8000/test?js/a.js&js/b.js
//      localhost:8000/test?css/a.css&css/b.css
