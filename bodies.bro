##! This script reassembles full HTTP bodies and raises an event with the
##! complete contents.

module HTTP;

export {
    ## Flag that indicates whether to hook request bodies.
    const hook_request_bodies = F &redef;

    ## Flag that indicates whether to hook reply bodies.
    const hook_reply_bodies = T &redef;

    ## The pattern applies 
    const hook_host_pattern = /.*/ &redef;

    ## Do not buffer more than this amount of bytes per HTTP message.
    const max_body_size = 50000000;

}

## Users write a handler for this event to process the current HTTP body.
global http_body: event(c: connection, is_orig: bool, 
                        data: string, size: count);

type body_info: record {
    data: string;
    size: count;
};

global bodies: table[string, bool] of body_info;

function notify_and_remove_body(c: connection, is_orig: bool)
    {
    local info = bodies[c$uid, is_orig];
    event http_body(c, is_orig, info$data, info$size);
    delete bodies[c$uid, is_orig];
    }

event http_begin_entity(c: connection, is_orig: bool)
    {
    if ( (is_orig && ! hook_request_bodies) ||
         (! is_orig && ! hook_reply_bodies) )
        return;

    if ( hook_host_pattern !in c$http$host )
        return;

    local info: body_info;
    info$data = "";
    info$size = 0;
    bodies[c$uid, is_orig] = info;
    
    # FIXME: Type inference should work here, but it doesn't.
    #bodies[c$uid, is_orig] = ["", 0];
    }

event http_entity_data(c: connection, is_orig: bool, length: count,
                       data: string)
    {
    if ( [c$uid, is_orig] !in bodies )
        return;

    local info = bodies[c$uid, is_orig];
    info$data += data;
    info$size += length;

    if ( info$size < max_body_size )
        return;

    notify_and_remove_body(c, is_orig);
    }

event http_end_entity(c: connection, is_orig: bool)
    {
    if ( [c$uid, is_orig] !in bodies )
        return;

    notify_and_remove_body(c, is_orig);
    }
