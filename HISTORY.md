Combo Handler History
=====================

0.2.0
-----

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
