#!/usr/bin/env node

/**
Cluster initialization file for the site. See the Cluster docs at
<http://learnboost.github.com/cluster/> for details about Cluster.
**/

var cluster = require('cluster'),
    server  = require('./lib/server');

cluster(server(require('./config')))
    .set('title', 'combohandler')

    .in('development')
        .set('workers', 1)
        .use(cluster.pidfiles())
        .use(cluster.cli())
        .use(cluster.logger('logs', 'debug'))
        .use(cluster.reload([
                'config.js',
                'index.js',
                'lib',
            ], {
                extensions: ['.js'],
                interval  : 1000,
                signal    : 'SIGQUIT'
            }))
        .use(cluster.debug())
        .listen(8000)

    .in('production')
        .use(cluster.pidfiles())
        .use(cluster.cli())
        .use(cluster.logger('logs'))
        .listen(8000);
