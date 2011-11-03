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

    http_body: event(c: connection, is_orig: bool, data: string, size: count);

As with all Bro HTTP scripts, `is_orig` differentiates requests from replies.
The field `data` contains the body and `size` holds the body length in bytes.

Because the keeping track of all HTTP bodies would likely exceed the
amount of available memory, we need to focus of a subset of HTTP message
bodies. The script offers the following variables in the namespace `HTTP` to do
so:

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
two conversing buddies. [My blog][fb-chat-post] contains a bit more details
about this script.

[fb-chat-post]: http://matthias.vallentin.net/blog/2011/06/analyzing-facebook-webchat-sessions-with-bro/
