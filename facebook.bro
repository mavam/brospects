##!
##! A Facebook analysis script.
##!
##! The script parses the HTTP body of Facebook JSON messages and reconstructs
##! a stream of chat messages from it.

# TODO:
#   - Add more message types.
#   - Parse other non-chat messages as well and establish the notion of a
#     session. To this end, we can use the actual closing message from Facebook
#     itself, which looks like this:
#         for (;;);{"t":"msg","c":"p_1111111111","s":18,"ms":[{
#                         "id":111111111111111, "window_id":1111111111,
#                         "type":"close_chat"}]}"

@load bodies

redef HTTP::hook_reply_bodies = T;
redef HTTP::hook_host_pattern = /[0-9]+\.channel\.facebook\.com/;

module Facebook;

export {
    redef enum Log::ID += { LOG };

    ## Describes the per-connection
    type Info: record {
        timestamp: string   &log;
        chat_from: string   &log;
        chat_to: string     &log;
        chat_msg: string    &log;
    };

    ## The types of AJAX messages.
    type MessageType: enum {
        CHAT                ##< A webchat message.
    };

    ## A chat message
    type ChatMessage: record
    {
        msg_type: MessageType;  ##< Message type.
        timestamp: string;  ##< Message timestamp.
        from: string;       ##< Name of the sender
        to: string;         ##< Name of the recipient.
        text: string;       ##< The actual message.
    };

	global log_facebook: event(rec: Info);
}

event bro_init()
	{
	Log::create_stream(Facebook::LOG, [$columns=Info, $ev=log_facebook]);
	}

## Extract text between two quotes.
function extract_quoted(str: string) : string
    {
    local q = find_last(str, /\"([^\"]|\\\")*\"$/);     # "
    return split(q, /\"/)[2];                           # "
    }

## Create a webchat message from JSON data.
function parse_fb_message(data: string) : ChatMessage
    {
    local msg: ChatMessage;

    local array = split(data, /,\"/);                   # "
    for ( i in array )
        {
        local val = array[i];
        if ( strstr(val, "time\":") > 0 )
            msg$timestamp = find_last(val, /[0-9]{13}/);
        else if ( strstr(val, "from_name\":\"") > 0 )
            msg$from = extract_quoted(val);
        else if ( strstr(val, "to_name\":\"") > 0 )
            msg$to = extract_quoted(val);
        else if ( strstr(val, "\"msg\":{\"text\":\"") > 0 )
            msg$text = extract_quoted(val);
        }

    return msg;
    }

## Reassemble the HTTP body of replies and look for Facebook chat messages.
event http_body(c: connection, is_orig: bool, data: string, size: count)
    {
    # Hackish heuristic that indicates we're dealing with a chat message.
    if (/^for \(;;\);\{\"t\":\"msg\".*text\":\"/ !in data)  #"
        return;

    local msg = parse_fb_message(data);

    local i: Info;
    i$timestamp = msg$timestamp;
    i$chat_from = msg$from;
    i$chat_to = msg$to;
    i$chat_msg = msg$text;

    Log::write(Facebook::LOG, i);
    }
