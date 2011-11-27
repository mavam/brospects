##! A Duqu detector. It builds a statemachine of the HTTP[S]-based C&C protocol
##! spoken by infected machines.
##!
##! Many thanks to Boldizsar Bencsath <boldi@crysys.hu> from CrySyS Lab for
##! providing Bro logs that that represent a Duqu session.
##!

module HTTP;

export {
    redef enum Notice::Type += {
        ## Indicates that we might have witnessed a Duqu infection.
        Potential_Duqu_Infection
    };

    redef record Info += {
        cookie: string &log &optional;
        content_type: string &log &optional;
    };

    ## The Duqu FSM.
    type DuquState: enum {
        JPEG_REQUEST,       # Initial GET request
        JPEG_REPLY,         # Response containing the JPEG
        START_EXFILTRATION, # POST request that initiates the data exfiltration
        ACK_EXFILTRATION,   # POST request that initiates the data exfiltration
        EXFILTRATING        # POST request containing the actual data
    };
}

## Keeps track of Duqu-infected machines.
global duqus: table[addr] of DuquState &read_expire=1hr;

event http_header(c: connection, is_orig: bool, name: string, value: string)
    {
    if ( is_orig && name == "COOKIE" )
        c$http$cookie = value;

    if ( name == "CONTENT-TYPE" )
        c$http$content_type = value;
    }

event http_message_done(c: connection, is_orig: bool, stat: http_message_stat)
    {
    if ( is_orig )
        {
        if ( c$http$method == "GET" &&
            /^PHPSESSID=[[:alnum:]]+$/ in c$http$cookie &&
            /([0-9]+){3}\.[0-9]+/ in c$http$host &&
            c$http$uri == "/" )
            duqus[c$id$orig_h] = JPEG_REQUEST;

        if ( c$http$method == "POST" &&
             c$id$orig_h in duqus &&
             duqus[c$id$orig_h] == JPEG_REPLY &&
             /^PHPSESSID=[[:alnum:]]+$/ in c$http$cookie &&
            /([0-9]+){3}\.[0-9]+/ in c$http$host &&
            c$http$uri == "/" &&
#            /multipart\/form-data/ in c$http$content_type &&
            c$http$request_body_len == 0 )
            duqus[c$id$orig_h] = START_EXFILTRATION;

        if ( c$id$orig_h in duqus &&
             (duqus[c$id$orig_h] == ACK_EXFILTRATION ||
              duqus[c$id$orig_h] == EXFILTRATING ) &&
             c$http$request_body_len > 0 )
            {
            duqus[c$id$orig_h] = EXFILTRATING;
            NOTICE([$note=Potential_Duqu_Infection,
                    $msg=fmt("Duqu exfiltrated %d bytes",
                             c$http$request_body_len),
                    $conn=c]);
            }
        }
    else
        {
        if ( c$id$orig_h in duqus )
            {
            if ( duqus[c$id$orig_h] == JPEG_REQUEST &&
                 c$http$status_code == 200 &&
                 /image\/jpeg/ in c$http$mime_type )
                {
                duqus[c$id$orig_h] = JPEG_REPLY;
                NOTICE([$note=Potential_Duqu_Infection,
                        $msg=fmt("Initial Duqu JPEG exchange"),
                        $conn=c]);
                }
            else
                delete duqus[c$id$orig_h]; # Purge unnecessary state early.
            }


        if ( c$id$orig_h in duqus &&
             duqus[c$id$orig_h] == START_EXFILTRATION &&
             c$http$status_code == 200 &&
             c$http$response_body_len == 0 )
            duqus[c$id$orig_h] = ACK_EXFILTRATION;
        }
    }
