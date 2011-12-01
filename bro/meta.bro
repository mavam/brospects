##! This script handles a special ``meta_event`` that the core generates for
##! each raised event. It does not work with git/master, but requires the
##! branch ``topic/matthias/meta-analysis`` to work properly.
##!
##! Ths script is mainly intended to profile the event load that Bro
##! experiences, which can be of quite different nature than the packet stream.
@load local

module Meta;

export {
    redef enum Log::ID += { LOG };

    type Info: record {
        ts: time     &log;      ##< The timestamp when the event was generated.
        name: string &log;      ##< The event name.
        size: count  &log;      ##< The size of the event in bytes.
    };

    global log_meta: event(rec: Info);
}

event meta_event(name: string, timestamp: time, size: count)
    {
    local rec: Meta::Info = [$ts=timestamp, $name=name, $size=size];
    Log::write(Meta::LOG, rec);
    }

event bro_init()
	{
    Log::create_stream(Meta::LOG, [$columns=Info, $ev=log_meta]);
	}
