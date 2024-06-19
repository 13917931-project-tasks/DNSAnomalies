spicy_add_analyzer(
    NAME dnsanomalies
    PACKAGE_NAME DNSAnomalies
    SOURCES dnsanomalies.spicy dnsanomalies.evt zeek_dnsanomalies.spicy
    SCRIPTS __load__.zeek main.zeek dpd.sig
)
