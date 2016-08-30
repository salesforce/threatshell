Commands
========

.. contents:: Index
   :depth: 2


Config Management Commands
--------------------------

config_add
++++++++++

Add a section or option to the config or change the existing
value of something in the config. **DON'T FORGET TO SAVE CHANGES!**
::

    positional (required) arguments:
      section     The section that will contain the specified option. Can be a
                  new section or existing
      option      The option name that is being set or updated. Can be a new
                  option or existing
      value       The value to be set

    optional arguments:
      -h, --help  show this help message and exit

config_dump
+++++++++++

Dump the config into a plaintext file in the threatshell
directory. If the plaintext file is detected on the next run of threatshell,
it will be loaded and the existing encrypted config file will be overwritten
with the newly encrypted file
::

    optional arguments:
      -h, --help    show this help message and exit
      -s, --screen  Dump the config to screen for viewing only

config_remove
+++++++++++++

Remove a section and/or option from the config
::

    positional arguments:
      section     The section that will contain the specified option. Must be an
                  existing section
      option      The option name that is removed. Must be an existing option

    optional arguments:
      -h, --help  show this help message and exit

config_save
+++++++++++

Save all config changes. Even changes via a dumped config. Note that saving
a modified dump file will require a restart of threatshell to take effect.


Tag Management Commands
-----------------------

add_tags
++++++++

Add new tags to the current session
::

    positional arguments:
      tags        One or more space delimited tags to be added

    optional arguments:
      -h, --help  show this help message and exit

list_tags
+++++++++

List all of the tags for the current session

remove_tags
+++++++++++

Remove one or more tags from the current session
::

    positional arguments:
      tags        One or more space delimited tags to be added

    optional arguments:
      -h, --help  show this help message and exit
      -a, --all   Remove all tags


Geo Location Commands
---------------------

geo
+++

Use MaxMind geolocation to find a given list of IPs and/or domains
::

    positional arguments:
      indicator(s)  One or more IPs and/or domains (space delimited)

geo_asn
+++++++

Use MaxMind geolocation to find the ASN information of a given domain or IP address
::

    positional arguments:
      indicator(s)  One or more IPs and/or domains (space delimited)

geo_country
+++++++++++

Use geolocation to find the country hosting a given domain name or IP address.
::

    positional arguments:
      target               The target domain or IP to geolocate

    optional arguments:
      -h, --help           show this help message and exit
      -cc, --country_code  Use country code instead of name

geo_update
++++++++++

Update (or install) the MaxMind geolocation database


OpenDNS Commands
----------------

Investigate API
+++++++++++++++

odns_category
~~~~~~~~~~~~~

Look up category information for a given domain from OpenDNS
::

   positional arguments:
     indicator        Specify the domain(s) to query for. Can be a space
                      delimited list of domains

   optional arguments:
     -h, --help       show this help message and exit
     -b, --use_batch  Use the batch lookup rather than a request per domain

odns_co_occurs
~~~~~~~~~~~~~~

Look up co-occurring domains for a given domain from OpenDNS
::

    positional arguments:
      indicator   Specify the domain(s) to query for. Can be a space delimited
                  list of domains

    optional arguments:
      -h, --help  show this help message and exit

odns_dns_info
~~~~~~~~~~~~~

Look up DNS info for a given domain or IP from OpenDNS
::

    positional arguments:
      indicator             Specify the domain(s)/IP(s) to query for. Can be a
                            space delimited list of domains

    optional arguments:
      -h, --help            show this help message and exit
      -rt {a,ns,mx,txt,cname}, --record_type {a,ns,mx,txt,cname}
                            Specify the type of DNS record to look up info for
      -irt {a,ns}, --ip_record_type {a,ns}
                            Specify the type of DNS records for IP lookup info

odns_mal_doms
~~~~~~~~~~~~~

Look up the latest malicious domains for a given IP address
or a space delimited list of IP addresses
::

    positional arguments:
      indicator   Specify the name server(s) to query for. Can be a space
                  delimited list of emails

    optional arguments:
      -h, --help  show this help message and exit

odns_mal_index
~~~~~~~~~~~~~~

Look up malicious status of domain from OpenDNS
::

    positional arguments:
      indicator        Specify the domain(s) to query for. Can be a space
                       delimited list of domains

    optional arguments:
      -h, --help       show this help message and exit
      -b, --use_batch  Use the batch lookup rather than a request per domain

odns_related_doms
~~~~~~~~~~~~~~~~~

Look up related domains for a given domain from OpenDNS
::

    positional arguments:
      indicator   Specify the domain(s) to query for. Can be a space delimited
                  list of domains

    optional arguments:
      -h, --help  show this help message and exit

odns_security_info
~~~~~~~~~~~~~~~~~~

Look up OpenDNS secure graph security feature rankings
::

    positional arguments:
      indicator   Specify the domain(s) to query for. Can be a space delimited
                  list of domains

    optional arguments:
      -h, --help  show this help message and exit

odns_whois
~~~~~~~~~~

Look up whois information for a given domain from OpenDNS
::

    positional arguments:
      indicator             Specify the domain to query for

    optional arguments:
      -h, --help            show this help message and exit
      -t, --history         Look up historical whois for the given domain
      -l LIMIT, --limit LIMIT
                            Set the limit of history entries to be returned

odns_whois_email
~~~~~~~~~~~~~~~~

Look up whois information from a given email or space delimited list of emails
from OpenDNS
::

    positional arguments:
      indicator             Specify the email(s) to query for. Can be a space
                            delimited list of emails

    optional arguments:
      -h, --help            show this help message and exit
      -l LIMIT, --limit LIMIT
                            Set the limit of entries to be returned

odns_whois_ns
~~~~~~~~~~~~~

Look up whois information from a given name server or space delimited list of
name servers from OpenDNS
::

    positional arguments:
      indicator             Specify the name server(s) to query for. Can be a
                            space delimited list of emails

    optional arguments:
      -h, --help            show this help message and exit
      -l LIMIT, --limit LIMIT
                            Set the limit of entries to be returned

Umbrella API
++++++++++++

umbrella_block
~~~~~~~~~~~~~~

Add a URL/domain to the OpenDNS Umbrella service block list

umbrella_list
~~~~~~~~~~~~~

List domains that are blocked via the OpenDNS Umbrella service

umbrella_unblock
~~~~~~~~~~~~~~~~

Remove a domain from the OpenDNS Umbrella service


PassiveTotal Commands
---------------------

pt_account
++++++++++

Get information about your PassiveTotal account

pt_add_tags
+++++++++++

Add tags to the associated query value
::

    positional arguments:
      query                 Add tags to this indicator

    optional arguments:
      -h, --help            show this help message and exit
      -t TAGS [TAGS ...], --tags TAGS [TAGS ...]
                            The tags to be added

pt_ahist
++++++++

Get historical information about your PassiveTotal account

pt_check_ddns
+++++++++++++

Check PassiveTotal to see if domain is on dynamic DNS
::

    positional arguments:
    domains     Domain(s) to check

    optional arguments:
    -h, --help  show this help message and exit

pt_check_monitor
++++++++++++++++

Check if you are monitoring a given domain/IP
::

    positional arguments:
      queries     Domain(s) and/or IP(s) to check monitoring status of

    optional arguments:
      -h, --help  show this help message and exit

pt_check_sinkhole
+++++++++++++++++

Check if the given IP is a sinkhole
::

    positional arguments:
      queries     IP(s) to check sinkhole status of

    optional arguments:
      -h, --help  show this help message and exit

pt_class
++++++++

Get the PassiveTotal threat classification for a domain
::

    positional arguments:
      queries     domain(s) to classify

    optional arguments:
      -h, --help  show this help message and exit

pt_compromised
++++++++++++++

Check PassiveTotal to see if domain was ever compromised
::

    positional arguments:
      queries     Domain(s) and/or IP(s) to check history of

    optional arguments:
      -h, --help  show this help message and exit

pt_domain_enrich
++++++++++++++++

Get domain enrichment metadata from PassiveTotal
::

    positional arguments:
      domains     specify one or more domains to get enrichment for

    optional arguments:
      -h, --help  show this help message and exit

pt_get_ssl_cert
+++++++++++++++

Get the SSL certificate for the given sha1
::

    positional arguments:
      queries     One or more sha1 hashes to get ssl certs for

    optional arguments:
      -h, --help  show this help message and exit

pt_get_tags
+++++++++++

Get tags for the associated query value
::

    positional arguments:
      query       Get tags for this indicator

    optional arguments:
      -h, --help  show this help message and exit

pt_host_components
++++++++++++++++++

Get detailed information about a host
::

    positional arguments:
      queries     The domain(s) to get component information for

    optional arguments:
      -h, --help  show this help message and exit

pt_host_trackers
++++++++++++++++

Get tracking codes for a domain or IP
::

    positional arguments:
      queries     The domain or IP to get tracking codes for

    optional arguments:
      -h, --help  show this help message and exit

pt_ip_enrich
++++++++++++

Get IP enrichment metadata from PassiveTotal
::

    positional arguments:
      ips         specify one or more ips to get enrichment for

    optional arguments:
      -h, --help  show this help message and exit

pt_malware_enrich
+++++++++++++++++

Get malware enrichment metadata from PassiveTotal
::

    positional arguments:
      query       specify one or more ips to get enrichment for

    optional arguments:
      -h, --help  show this help message and exit

pt_notifications
++++++++++++++++

Get notifications posted to your PassiveTotal account
::

    optional arguments:
      -h, --help            show this help message and exit
      -t TYPE, --type TYPE  Specify the notification type to retrieve

pt_org_info
+++++++++++

Get information about your account's organization

pt_org_teamstream
+++++++++++++++++

Get the teamstream for your account's organization
::

    optional arguments:

      -h, --help            show this help message and exit

      -s {web,api}, --source {web,api}
                            Source of the action

      -dt MM-DD-YYYY HH:MM:SS
                            Datetime to be used as a filter

      -t TYPE, --type TYPE  Type of tagstream event to retrieve. Choose from any
                            of the following: search, classify, tag, watch

      -f FOCUS, --focus FOCUS
                            Specify a specific value that was used as the
                            focus of the tagstream

pt_osint_enrich
+++++++++++++++

Get OSInt enrichment metadata from PassiveTotal
::

    positional arguments:
      query       specify one or more indicators to get enrichment for

    optional arguments:
      -h, --help  show this help message and exit

pt_pdns
+++++++

Get passive DNS data from PassiveTotal
::

    positional arguments:
    domains               One or more domains to query for

    optional arguments:

    -h, --help            show this help message and exit

    -d {next,previous}, --direction {next,previous}
                        Pagination direction

    -p PAGE, --page PAGE  Page ID to request

    -s SOURCES [SOURCES ...], --sources SOURCES [SOURCES ...]
                        select one or more sources to process with

    -b yyyy-mm-dd, --start yyyy-mm-dd
                        only show data starting on given date

    -e yyyy-mm-dd, --end yyyy-mm-dd
                        only show data up to given date

pt_rm_tags
++++++++++

Remove tags for the associated query value
::

    positional arguments:
      query                 Add tags to this indicator

    optional arguments:
      -h, --help            show this help message and exit
      -t TAGS [TAGS ...], --tags TAGS [TAGS ...]
                            The tags to be removed

pt_search_ssl
+++++++++++++

Search SSL Cert fields for particular values
::

    positional arguments:
      query                 The value of the field to search with

    optional arguments:

      -h, --help            show this help message and exit

      -f FIELD, --field FIELD
                            The field to search. Valid choices are -
                            issuerSurname, subjectOrganizationName,
                            issuerCountry, issuerOrganizationUnitName,
                            fingerprint, subjectOrganizationUnitName,
                            serialNumber, subjectEmailAddress, subjectCountry,
                            issuerGivenName, subjectCommonName,
                            issuerCommonName, issuerStateOrProvinceName,
                            issuerProvince, subjectStateOrProvinceName,
                            sha1, sslVersion, subjectStreetAddress,
                            subjectSerialNumber, issuerOrganizationName,
                            subjectSurname, subjectLocalityName,
                            issuerStreetAddress, issuerLocalityName,
                            subjectGivenName, subjectProvince,
                            issuerSerialNumber, issuerEmailAddress

pt_search_tags
++++++++++++++

Search tags for the associated query value
::

    positional arguments:
      queries     Add tags to this indicator

    optional arguments:
      -h, --help  show this help message and exit

pt_set_class
++++++++++++

Set the classification for a domain/IP
::

    positional arguments:
      query                 The domain or IP to classify

    optional arguments:

      -h, --help            show this help message and exit

      -c CLASS, --classification CLASS
                            Classification for the given indicator. Choose
                            from one of the following: malicious,
                            suspicious, non-malicious, unknown

pt_set_compromised
++++++++++++++++++

Set the compromised status for a domain/IP
::

    positional arguments:
      query                 The domain or IP to set compromised status for

    optional arguments:
      -h, --help            show this help message and exit
      -s STATUS, --status STATUS
                            Classification for the given indicator. Can be
                            true/false or t/f for short

pt_set_ddns
+++++++++++

Set the dynamic DNS status for a domain
::

    positional arguments:
      query                 The domain to set dynamic DNS status for

    optional arguments:
      -h, --help            show this help message and exit
      -s STATUS, --status STATUS
                            Status for the given indicator. Can be true/false or
                            t/f for short

pt_set_monitor
++++++++++++++

Set the monitoring status for a domain/IP
::

    positional arguments:
      query                 The domain or IP to set monitor status for

    optional arguments:
      -h, --help            show this help message and exit
      -s STATUS, --status STATUS
                            Classification for the given indicator. Can be
                            true/false or t/f for short

pt_set_sinkhole
+++++++++++++++

Set the sinkhole status for an IP
::

    positional arguments:
      query                 The IP to set sinkhole status for

    optional arguments:
      -h, --help            show this help message and exit
      -s STATUS, --status STATUS
                            Classification for the given indicator. Can be
                            true/false or t/f for short

pt_source_config
++++++++++++++++

Get details and configurations for intel sources
::

    positional arguments:
      sources     Name of intel source(s) to pull back (defaults to all)

    optional arguments:
      -h, --help  show this help message and exit

pt_ssl_history
++++++++++++++

Get the SSL Cert history for a given IP or domain
::

    positional arguments:
      queries     The domain or IP to get cert history for

    optional arguments:
      -h, --help  show this help message and exit

pt_subdom_enrich
++++++++++++++++

Get Subdomain enrichment metadata from PassiveTotal
::

    positional arguments:
      query       specify one or more domains to get enrichment for

    optional arguments:
      -h, --help  show this help message and exit

pt_tracker_search
+++++++++++++++++

Get hosts matching a specific tracking ID
::

    positional arguments:
      query           The value to use for the search

    optional arguments:

      -h, --help      show this help message and exit

      --type TRACKER  The type of tracker to use for the search. Allowed choices
                      are the following - YandexMetricaCounterId, ClickyId,
                      GoogleAnalyticsAccountNumber, GoogleAnalyticsTrackingId,
                      NewRelicId, MixpanelId

pt_unique_pdns
++++++++++++++

Get deduplicated passive DNS data from PassiveTotal
::

    positional arguments:
      domains               One or more domains to query for

    optional arguments:

      -h, --help            show this help message and exit

      -d {next,previous}, --direction {next,previous}
                            Pagination direction

      -p PAGE, --page PAGE  Page ID to request

      -s SOURCES [SOURCES ...], --sources SOURCES [SOURCES ...]
                            select one or more sources to process with

      -b yyyy--mm-dd, --start yyyy-mm-dd
                            only show data starting on given date

      -e yyyy-mm-dd, --end yyyy-mm-dd
                            only show data up to given date

pt_whois
++++++++

Get whois data from PassiveTotal
::

    positional arguments:
      queries               specify one or more domains/ips to get whois
                            data for

    optional arguments:
      -h, --help            show this help message and exit
      -c, --compact_record  compress the whois record into deduplicated format

pt_whois_search
+++++++++++++++

Search fields in Whois data from PassiveTotal
::

    positional arguments:
      queries               specify one or more domains to get whois data for

    optional arguments:

      -h, --help            show this help message and exit

      -f FIELD, --field FIELD
                            Whois field to execute search on. Searchable fields
                            can any of the following: name, domain, email,
                            organization, address, phone, nameserver

ThreatQuotient Commands
-----------------------

tqadd
+++++

Add an indicator to ThreatQ
::

    positional arguments:
      indicator             Specify the indicator to be added

    optional arguments:
      -h, --help            show this help message and exit

      -c, --class_type      indicator class
      choices: {network, host}

      -t , --type           indicator type
      choices:
        {
            SHA-512, Email Address, String, Filepath, URL, SHA-256,
            Email Attachment, URL Path, Email Subject, Fuzzy Hash,
            Filename, SHA-384, IP Address, CIDR Block, Mutex, SHA-1,
            Registry Key, FQDN, User-agent, X-Mailer, MD5
        }

      -s, --status          indicator status
      choices:
        {
            CSIRT_Review, FPC, Review, Active, Indirect, Expired, Non-malicious
        }

tqcs
++++

Change indicator status in ThreatQ
::

    positional arguments:
      indicator_id          Specify the indicator ID to change the status of

    optional arguments:
      -h, --help            show this help message and exit
      --class_type {network,host}
                            indicator class
      --status              indicator status to set indicator to
      choices:
        {
            CSIRT_Review, FPC, Review, Active, Indirect, Expired, Non-malicious
        }

tq_search
+++++++++

Search ThreatQ for an indicator
::

    positional arguments:
      indicator   Specify the indicator to query for

    optional arguments:
      -h, --help  show this help message and exit

tqstatus
++++++++

List available ThreatQ indicator statuses

tqtypes
+++++++

List available ThreatQ indicator types


Shadow Server Commands
----------------------

ss_asnum_prefix
+++++++++++++++

Look up ASN prefix information for an ASN number from
Shadow Server ASN

ss_asorigin
+++++++++++

Look up ASN origin information about the given domain or IP from Shadow Server
::

    positional arguments:
      indicator   Specify the domain(s)/IP(s) to query for. Can be a space
                  delimited list of domains and/or IPs

    optional arguments:
      -h, --help  show this help message and exit

ss_aspeers
++++++++++

Look up ASN peer information about a given domain or IP from Shadow Server
::

    positional arguments:
      indicator   Specify the domain(s)/IP(s) to query for. Can be a space
                  delimited list of domains and/or IPs

    optional arguments:
      -h, --help  show this help message and exit


Cymru Commands
--------------

cymru_asinfo
++++++++++++

Look up ASN information about a given domain or IP from Cymru
::

    positional arguments:
      indicator   Specify the domain(s)/IP(s) to query for. Can be a space
                  delimited list of domains and/or IPs

    optional arguments:
      -h, --help  show this help message and exit

cymru_asnum_info
++++++++++++++++

Look up ASN information about a given ASN number from Cymru
::

    positional arguments:
      indicator   Specify the number(s) to query for. Can be a space delimited
                  list of ASN numbers

    optional arguments:
      -h, --help  show this help message and exit
