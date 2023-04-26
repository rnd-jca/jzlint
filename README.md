# JZLint

JZLint is a port of [ZLint](https://github.com/zmap/zlint) in Java.

* To support differential testing between Go and Java libraries that process certificates and CRLs.
* To provide a more direct integration in the Java ecosystem.

JZLint is compatible with Java 8.

## Lints

### Missing Lints

Following lints of ZLint are not implemented yet:

1. e_ext_ian_uri_host_not_fqdn_or_ip
2. e_ext_san_uri_host_not_fqdn_or_ip
3. e_name_constraint_not_fqdn
4. e_ext_tor_service_descriptor_hash_invalid
5. e_dnsname_contains_bare_iana_suffix
6. n_dnsname_wildcard_left_of_public_suffix
7. e_ext_nc_intersects_reserved_ip
8. e_ext_san_contains_reserved_ip
9. e_ext_tor_service_descriptor_hash_invalid
10. n_contains_redacted_dnsname
11. w_subject_contains_malformed_arpa_ip
12. e_subject_contains_reserved_arpa_ip
13. e_subject_contains_reserved_ip
14. e_san_dns_name_onion_not_ev_cert
15. e_utc_time_not_in_zulu
16. e_san_dns_name_onion_invalid
17. e_utc_time_does_not_include_seconds
18. e_international_dns_name_not_nfc
19. e_generalized_time_does_not_include_seconds

### Additional lints

There exists some additional lints.
These are located in the subproject jlint-ext.

### OCSP lints

There exist lints for OCSP responses.
These are located in the subproject jlint-ocsp.

### Lints using the issuer

There exist lints that have the issuer of the certificate as an additional input.
These are located in the subproject jlint-issuer.


