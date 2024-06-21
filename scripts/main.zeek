@load base/protocols/conn/removal-hooks

module dnsanomalies;

export {
	## Log stream identifier.
	redef enum Log::ID += { LOG };
	
	## The ports to register dnsanomalies for.
	const ports = {
		# TODO: Replace with actual port(s).
		53/udp,
                5353/udp
	} &redef;

	## Record type containing the column fields of the dnsanomalies log.
	type Info: record {
		## Timestamp for when the activity happened.
		ts: time &log;
		## Unique ID for the connection.
		uid: string &log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id: conn_id &log;
		
	
		#msg_type: string &optional &log;
		flags_byte: string &optional &log;
		payload_size: count &optional &log;

		# TODO: Adapt subsequent fields as needed.

		## Request-side payload.
		#request: string &optional &log;
		## Response-side payload.
		#reply: string &optional &log;
	};

	## A default logging policy hook for the stream.
	global log_policy: Log::PolicyHook;

	## Default hook into dnsanomalies logging.
	global log_dnsanomalies: event(rec: Info);

	## dnsanomalies finalization hook.
	global finalize_dnsanomalies: Conn::RemovalHook;
}

#redef record connection += {
#	dnsanomalies: Info &optional;
#};

redef likely_server_ports += { ports };

# TODO: If you're going to send file data into the file analysis framework, you
# need to provide a file handle function. This is a simple example that's
# sufficient if the protocol only transfers a single, complete file at a time.
#
# function get_file_handle(c: connection, is_orig: bool): string
#	{
#	return cat(Analyzer::ANALYZER_DNSANOMALIES, c$start_time, c$id, is_orig);
#	}

event zeek_init() &priority=5
	{
	Log::create_stream(dnsanomalies::LOG, [$columns=Info, $ev=log_dnsanomalies, $path="dnsanomalies", $policy=log_policy]);

	Analyzer::register_for_ports(Analyzer::ANALYZER_DNSANOMALIES, ports);

	# TODO: To activate the file handle function above, uncomment this.
	# Files::register_protocol(Analyzer::ANALYZER_DNSANOMALIES, [$get_file_handle=dnsanomalies::get_file_handle ]);
	}

# Initialize logging state.
#hook set_session(c: connection)
#	{
#	if ( c?$dnsanomalies )
#		return;
#
#	c$dnsanomalies = Info($ts=network_time(), $uid=c$uid, $id=c$id);
#	Conn::register_removal_hook(c, finalize_dnsanomalies);
#	}

#function emit_log(c: connection)
#	{
#	if ( ! c?$dnsanomalies )
#		return;
#
#	Log::write(dnsanomalies::LOG, c$dnsanomalies);
#	delete c$dnsanomalies;
#	}


# Example event defined in dnsanomalies.evt.
event dnsanomalies::message(c: connection, is_orig: bool, payload: string, flags_data: string) &priority=5
	{
	#$msg_type=msg_type
	Log::write(dnsanomalies::LOG, [$ts=network_time(), $uid=c$uid, $id=c$id, $flags_byte=flags_data, $payload_size=|payload|]);
	#hook set_session(c);
	local msg_type: string;
	#local info = c$dnsanomalies;
	if ( is_orig ) {
		#info$request = payload;
		msg_type="REQUEST";
		}
	else
		{
		#info$reply = payload;
		msg_type="REPLY";
		}
	#if (flags_data=="-98"){
		#if (|payload|>250){

			#}
		#}
	}


#hook finalize_dnsanomalies(c: connection)
#	{
#	# TODO: For UDP protocols, you may want to do this after every request
#	# and/or reply.
#	emit_log(c);
#	}
