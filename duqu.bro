##! A very rough Duqu detector based on http://bit.ly/duqu-analysis.

module HTTP;

export {
	redef enum Notice::Type += {
		## Indicates that we might have witnessed a Duqu infection
	    Potential_Duqu_Infection
	};

    redef record Info += {
        cookie: string &optional;
        content_type: string &optional;
    };

    ## The Duqu FSM.
    type DuquState: enum {
        GIF_REQUEST,
        GIF_REPLY,
        JPEG_REQUEST,
        JPEG_REPLY
    };
}

## Keeps track of Duqu-infected machines.
global duqus: table[addr] of DuquState;

# Track the cookie value inside HTTP.
event http_header(c: connection, is_orig: bool, name: string, value: string)
    {
    if ( is_orig && name == "COOKIE" )
        c$http$cookie = value;

    if ( name == "CONTENT_TYPE" )
        c$http$content_type = value;
    }

event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string)
    {
    if ( method == "GET" &&
        /^PHPSESSIONID=[[:alnum]]+$/ in c$http$cookie &&
        /([0-9]+){3}\.[0-9]/ in c$http$host &&
        unescaped_URI == "/" )
        duqus[c$id$orig_h] = GIF_REQUEST;

    if ( method == "POST" &&
         c$id$orig_h in duqus && 
         duqus[c$id$orig_h] == GIF_REPLY &&
         /^PHPSESSIONID=[[:alnum]]+$/ in c$http$cookie &&
        /([0-9]+){3}\.[0-9]/ in c$http$host &&
        unescaped_URI == "/" &&
        c$http$content_type == "multipart/form-data" )
        {
        duqus[c$id$orig_h] = JPEG_REQUEST;
       NOTICE([$note=Potential_Duqu_Infection,
               $msg="Duqu JPEG REQUEST",
               $conn=c,
               $identifier=cat(c$id$orig_h,duqus[c$id$orig_h])]);
        }
    }

event http_reply(c: connection, version: string, code: count, reason: string)
	{
	if ( c$id$orig_h in duqus && 
	     duqus[c$id$orig_h] == GIF_REQUEST &&
	     version == "HTTP/1.1" && 
	     code == 200 &&
	     c$http$content_type == "image/gif" )
	   {
	   duqus[c$id$orig_h] = GIF_REPLY;
       NOTICE([$note=Potential_Duqu_Infection,
               $msg="Duqu GIF Acknowledgement",
               $conn=c,
               $identifier=cat(c$id$orig_h,duqus[c$id$orig_h])]);
	   }

	if ( c$id$orig_h in duqus && 
	     duqus[c$id$orig_h] == JPEG_REQUEST &&
	     version == "HTTP/1.1" && 
	     code == 200 &&
	     c$http$response_body_len == 0 )
	   {
	   duqus[c$id$orig_h] = JPEG_REPLY;
       NOTICE([$note=Potential_Duqu_Infection,
               $msg="Duqu JPEG Acknowledgement",
               $conn=c,
               $identifier=cat(c$id$orig_h,duqus[c$id$orig_h])]);

	   delete duqus[c$id$orig_h];
	   }
	}
