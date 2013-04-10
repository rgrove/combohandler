// BadRequest is used for all filesystem-related errors, including when a
// requested file can't be found (a NotFound error wouldn't be appropriate in
// that case since the route itself exists; it's the request that's at fault).
function BadRequest(message) {
    Error.captureStackTrace(this, BadRequest);
    this.name = 'BadRequest';
    this.message = message;
}

require('util').inherits(BadRequest, Error);

exports = module.exports = BadRequest;
