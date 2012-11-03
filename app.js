#!/usr/bin/env node

var server = require('./lib/server');
server(require('./config')).listen(8000);
