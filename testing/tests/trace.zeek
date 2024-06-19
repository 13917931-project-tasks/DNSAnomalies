# @TEST-DOC: Test Zeek parsing a trace file through the dnsanomalies analyzer.
#
# @TEST-EXEC: zeek -Cr ${TRACES}/dns_tunneling.pcap ${PACKAGE} %INPUT >output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff dnsanomalies.log

# TODO: Adapt as suitable. The example only checks the output of the event
# handlers.

#event dnsanomalies::message(c: connection, is_orig: bool, payload: string)
#    {
#    print fmt("Testing dnsanomalies: [%s] %s %s", (is_orig ? "request" : "reply"), c$id, payload);
#    }
