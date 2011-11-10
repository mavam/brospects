This repository is a mixed bag of Bro scripts that are too specific to be
included in the official [Bro scripts
repository](http://git.bro-ids.org/bro-scripts.git). The scripts are
of expirimental nature and might have a few edges, so you are welcome to ping
me for feedback and clarifications.

Please see the file `COPYING` for the licence details.

Documentation
=============

bodies.bro
----------
This script reassembles HTTP bodies and raises an event with the complete
contents. Concretely, it reassembles the current request and/or response body
via the `http_entity_{begin,data,end}` events and raises the new event
`http_body` which has the following signature:

    http_body_complete: event(c: connection);

Upon handling `http_body_complete`, you can be sure that `c$http$body` contains
the full string of the HTTP response unless the body exceeds
`HTTP::max_body_size` bytes, in which case the body is chopped off at that
size.

Aside from `c$http$body`, this script adds a second field to `c$http` named
`reassembl_body` which determines whether the current connection should
reassemble the body. For example, if you observe some suspicious header value,
you could set `c$http$reassembl_body = T` and hand the `http_body_complete`
event. Note that this flag is *per connection* and not per HTTP message, which
means you would need to turn it off after handling `http_body_complete` if you
wanted body reassembly at the HTTP message level.

Because the keeping track of all HTTP bodies would likely exceed the amount of
available memory, we need to focus of a subset of HTTP message bodies. The
script offers the following variables in the HTTP namespace in addition to
`c$http$reassembl_body`:

    ## Flag that indicates whether to hook request bodies.
    const hook_request_bodies = F &redef;

    ## Flag that indicates whether to hook reply bodies.
    const hook_reply_bodies = T &redef;

    ## The pattern applies 
    const hook_host_pattern = /.*/ &redef;

    ## Do not buffer more than this amount of bytes per HTTP message.
    const max_body_size = 50000000;

Requires Bro 2.x

facebook.bro
------------

This script analyses Facebook webchat sessions and extracts messages between
two conversing buddies; it creates a file `facebook.log`.
[My blog][fb-chat-post] contains a bit more details about this script.

Requires Bro 2.x

[fb-chat-post]: http://matthias.vallentin.net/blog/2011/06/analyzing-facebook-webchat-sessions-with-bro/
