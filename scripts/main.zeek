@load base/protocols/conn/removal-hooks

module dnsanomalies;

export {
	## Log stream identifier.
	redef enum Log::ID += { LOG };
	
	global counter = 0;
	
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
		
		query: string &optional &log;
		entropy: double &optional &log;
		
		msg_type: string &optional &log;
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

function entropy(data: string):double
	{
	local result = 0.0;
	local words: vector of string;
	local repetition: vector of string;
	local total = vector(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,0, 0, 0, 0,0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);


	for (d in data)
		{
		
		words += d;
		
		}
	for (a in words)
	{
		if (|repetition|==0)
		{
			repetition += words[0];
			total[0]+=1;
		}
		else
		{
			counter=0;
			for (b in repetition) {
				
				if (repetition[b]==words[a])
					{
						total[b]+=1;
						counter=1;
						break;
					
					}
					
				else {
				
					#print fmt("%s!=%s",repetition[b],words[a]);
				}
			}
			if (counter==0){
				repetition+=words[a];
				#print words[a];
				total[|repetition|]+=1;

			}
		
		}
		
	}
	
	
	for (c in total)
		{
		if (total[c]>0){
		#print total[c];
		}
		}
	for (c in repetition){
		#print repetition[c];
	}
	
	for (t in total){
		if (total[t]>=1)
		{
		local freq: double;
		local qtt: double;
		local len: double;
		len = |data|;
		qtt = total[t];
		freq=0.0;
		freq = ((qtt)/(len));
		#print freq, qtt,len;
		result += ((freq)*(log2(freq)))*(-1);
		#print result;
		}
		}
	

	
		
	#result = result * (-1);
	
	return result;
	
}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) &priority=5
{
	local entropy_result = entropy(query);
	
	#total_entropy += entropy(query);
	#total_queries += 1;
	
	#if (entropy_result >= 3.8){
	Log::write(dnsanomalies::LOG, [$ts=network_time(), $uid=c$dns$uid, $id=c$dns$id, $query=c$dns$query, $entropy=entropy_result]);	
	#}
}

# Example event defined in dnsanomalies.evt.
event dnsanomalies::message(c: connection, is_orig: bool, payload: string, flags_data: string) &priority=5
	{
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
	if (flags_data=="-98"){
		if (|payload|>250){
			Log::write(dnsanomalies::LOG, [$ts=network_time(), $uid=c$uid, $id=c$id, $msg_type=msg_type, $flags_byte=flags_data, $payload_size=|payload|]);
			}
		}
	}


#hook finalize_dnsanomalies(c: connection)
#	{
#	# TODO: For UDP protocols, you may want to do this after every request
#	# and/or reply.
#	emit_log(c);
#	}
