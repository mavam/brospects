# 
# A Facebook analysis script.
#
# The script parses the HTTP body of Facebook JSON messages and reconstructs a
# stream of chat messages from it.
#

@load http-request
@load http-reply

module HTTP;

export
{
    redef enum Notice +=
    {
        Facebook_Chat_Start,
        Facebook_Chat_Message,
        Facebook_Chat_End
    };

    # A chat message
    type ChatMessage: record
    {
        timestamp: string;  # Message timestamp.
        from: string;       # Name of the sender
        to: string;         # Name of the recipient.
        text: string;       # The actual message.
    };

    type ChatSession: record
    {
        start: time;        # Unix timestamp of first message.
        end: time;          # Unix timestamp of last message.
        n: count;           # Total number of messages in session.
    };
}

type HTTPBody: record
{
    content_length: count;      # Value from the CONTENT-LENGTH header.
    size: count;                # Current size of accumulated body.
    data: string;               # Body data.
};

const facebook_log = open_log_file("facebook") &redef;

# If a HTTP body spans multiple events, this buffer accumulates the chunks.
global bodies: table[conn_id] of HTTPBody;

# Chats index by HTTP session ID.
global chats: table[conn_id] of ChatSession;

function new_chat_session() : ChatSession
{
    local s: ChatSession;

    s$start = network_time();
    s$end = s$start;
    s$n = 0;

    return s;
}

function new_http_body() : HTTPBody
{
    local body: HTTPBody;

    body$size = 0;
    body$data = "";

    return body;
}

# Extract text between two quotes.
function extract_quoted(str: string) : string
{
    local q = find_last(str, /\"([^\"]|\\\")*\"$/);
    return split(q, /\"/)[2];
}

function parse_fb_message(data: string) : ChatMessage
{
    local msg: ChatMessage;

    local array = split(data, /,\"/);     # "
    for (i in array)
    {
        local val = array[i];
        if (strstr(val, "time\":") > 0)
            msg$timestamp = find_last(val, /[0-9]{13}/);
        else if (strstr(val, "from_name\":\"") > 0)
            msg$from = extract_quoted(val);
        else if (strstr(val, "to_name\":\"") > 0)
            msg$to = extract_quoted(val);
        else if (strstr(val, "\"msg\":{\"text\":\"") > 0)
            msg$text = extract_quoted(val);
    }

    return msg;
}

function report_message(c: connection, msg: ChatMessage)
{
    local format = "%s (%s -> %s) %s";
    local message = fmt(format, msg$timestamp, msg$from, msg$to, msg$text);
    NOTICE([$note=Facebook_Chat_Message, $conn=c, $msg = message]);
    print facebook_log, message;
}

# For requests, look at the HOST header to determine whether we're expecting a
# potential chat message. For replies, record the size of the HTTP entity to
# make sure we reassemble it completely.
event http_header(c: connection, is_orig: bool, name: string, value: string)
{
    local id = c$id;
    if (is_orig && name == "HOST" && /[0-9]+\.channel\.facebook\.com/ in value)
    {
        if (id !in chats)
            chats[id] = new_chat_session();
    }
    else if (! is_orig && name == "CONTENT-LENGTH")
    {
        if (id !in chats)
            return;
       
        # If we have the current ID is still in the message buffer when seeing
        # a new reply, it means the the previous message has not been received
        # in its entirety. That is, there is some partial HTTP body hanging in
        # the buffer that we could try to parse at some point.
        if (id in bodies)
            print fmt("warning: ignoring incomplete HTTP body in %s", id);

        bodies[id] = new_http_body();
        bodies[id]$content_length = to_count(value);
    }
}

# Reassemble the HTTP body of replies and look for Facebook chat messages.
event http_entity_data(c: connection, is_orig: bool, length: count,
        data: string)
{
    local id = c$id;
    if (id !in bodies)
        return;

    local body = bodies[id];

    body$data = cat(body$data, data);

    if (body$size + length < body$content_length)
    {
        # Accumulate partial HTTP body data and return.
        body$size += length;
        return;
    }

    local chat = chats[id];
    chat$end = network_time();
    ++chat$n;

    # Hackish heuristic that indicates we're dealing with a chat message.
    if (/^for \(;;\);\{\"t\":\"msg\".*text\":\"/ in body$data)
    {
        local msg = parse_fb_message(body$data);
        report_message(c, msg);
    }
    
    delete bodies[id];
}

# Evict chat session state. 
# TODO: it would be nice to use the actual closing message from Facebook
# itself, which looks similar to:
# for (;;);{"t":"msg","c":"p_1111111111","s":18,"ms":[{"id":111111111111111,
#           "window_id":1111111111,"type":"close_chat"}]}"
event connection_state_remove(c: connection)
{
    local id = c$id;
    if (id !in chats)
        return;

    local session = chats[id];
#    print fmt("chat session ended (%s, %d messages)",
#            session$end - session$start, session$n);

    delete chats[id];
}
