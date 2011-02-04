Combo Handler
=============

This is a simple combo handler for Node.js. It works just like the combo handler
service on the Yahoo! CDN, which you'll be familiar with if you've used YUI.
It's compatible with the YUI 3 Loader, so you can use it to host YUI, but you
can also use it with any other JavaScript and CSS if you're willing to construct
the combo URLs yourself.

The combo handler itself doesn't perform any caching or compression, but stick
Nginx or something in front of it and you should be ready to rock in production.

Installation
------------

Grab the code from the [GitHub repo][repo]:

    git clone git://github.com/rgrove/combohandler.git

Rename `config.sample.js` to `config.js` and edit it to your liking, then fire
up the combo handler using [Spark][spark] or [Spark2][spark2].

[repo]: https://github.com/rgrove/combohandler
[spark]: https://github.com/senchalabs/spark
[spark2]: https://github.com/davglass/spark2

License
-------

Copyright (c) 2011 Ryan Grove <ryan@wonko.com>.

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
