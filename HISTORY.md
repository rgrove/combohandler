Combo Handler History
=====================

0.2.2 (2013-04-21)
------------------

* Changed default `combine` middleware to return an array of middleware instead
  of a function, allowing addition of bundled middlware depending on configured
  values. (Express flattens any arrays passed as route callbacks)

* Changed default error handler to pass the error to `next()` when it isn't a
  `BadRequest`, which was itself extracted to a separate file.

* Changed CSS `url()` rewriter to use built-in `path` methods instead of custom
  algorithm, with expanded test coverage.

* Added `bodyContents` and `relativePaths` arrays to `res.locals` object in the
  default `combine` middleware, allowing subsequent middleware access to those
  values.

* Added `cssUrls` middleware, an extraction of the CSS `url()` rewriter, with
  the optional capability of rewriting `@import` statements as well.

* Added `dynamicPath` middleware, supporting route params (e.g., `:version`)
  that point to different trees under the same filesystem root.

* Added `respond` middleware for convenience. It simply responds 200 with the
  contents of the `res.body` property.

* Added code coverage with `istanbul`.

* Added Travis support.

* Added [Daniel Stockman](https://github.com/evocateur) as a maintainer.

* Updated mocha dependency to 1.9.0.

* Updated express dependency to 3.2.x. [Eric Ferraiuolo]

0.2.1 (2013-04-01)
------------------

* Added a `basePath` config option that can be used to specify a
  non-combohandled base path. Relative URLs in combohandled CSS files will
  be automatically rewritten to be relative to this base path rather than the
  combo URL. [Ryan Cannon]


0.2.0 (2012-11-03)
------------------

* Supports Express 3.0.

* Removed support for Cluster, since it's dead.

* Added support for symlinks that point to files outside the root path.

* Added support for setting `Cache-Control` and `Expires` headers via the
  `maxAge` config property. [Daniel Stockman]

* Errors now provide more descriptive messages. [Daniel Stockman]

* Deny requests with non-whitelisted or differing MIME types. [Daniel Stockman]

* Return a quick error on requests that are obviously truncated or otherwise
  mangled. [Daniel Stockman]


0.1.3 (2011-10-31)
------------------

* Use Cluster instead of Spark2.


0.1.2 (2011-07-11)
------------------

* Chasing the latest Express and Connect versions again.


0.1.1 (2011-04-12)
------------------

* Now works with latest Express (2.x) and Connect (1.x).


0.1.0 (2011-02-05)
------------------

* Initial release.
