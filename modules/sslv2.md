# SSLv2

SSL Module can analyze the SSL configuration of a server by connecting to it.
It is designed to be fast and comprehensive and should help organizations and testers identify misconfigurations affecting their SSL servers.

By default, the SSL module runs in full mode, where it will run all tests including the cipher suite tests which are very noisy. It is possible to disable the cipher tests by selecting the fast mode, i.e., changing the configuration key **ssl_mode** to **fast**.

You can also run only specific cypher suites at a time, by changing **cypher_mode** to one of **sslv2**, **sslv3**, **tlsv1**, **tlsv1_1**, **tlsv1_2**, **tlsv1_3**.


## SSLv2 Request Example

```
curl -v -L https://api.binaryedge.io/v1/tasks -d '{"type":"scan", "options":[{"targets":["X.X.X.X"], "ports":[{"port":443, "protocol":"tcp", "modules":["sslv2"], "config":{}}]}]}' -H "X-Token:<Token>"
```

### SSLv2 Request Options

These are optional parameters that can alter the behaviour of the module. These options can be inserted into the "config" object on the request.

  * sni - Set HTTPS Server Name Indication
    * "config":{"sni":"google.com"}
  * disable_cyphers - Disable the cipher tests
    * "config":{"disable_cyphers":true}
  * cypher_mode - Run only specific cipher tests
    * "config":{"cypher_mode":"tls1_3"}
  * robot - Run only ROBOT vuln detection
    * "config":{"robot":true}

## SSL VS SSLv2

### Bug Fixes
- certificate validation against hostname was bugged on the original SSL module, new field certificate_matches_hostname now shows the correct information
- certificate subject public keys generated with DSA would trigger errors when parsing

### Added features
- added ROBOT vulnerability
- added CRL checking
- added TLSv1.3
- added Symantec distrust timeline

### Misc
- standardized JSON keys to snake case only
- timestamps formats changed
- some enumerated fields now only appear as strings, the int value had no real meaning
- removed trust_stores key, which was an out-of-context accumulation of path_validation_result_list from all the certificates in a chain
- other minor schema changes (see below)

## Schema

### SSLv2 Event Schema

```json
{
  "result": {
    "data": {
      "ciphers": {
        "tlsv1_2": {
          "errored_cipher_list": [],
          "preferred_cipher": {
            "ssl_version": "string",
            "is_anonymous": "boolean",
            "openssl_name": "string",
            "post_handshake_response": "string",
            "dh_info": {
              "Order": "string",
              "A": "string",
              "B": "string",
              "Type": "string",
              "Prime": "string",
              "Seed": "string",
              "Field_Type": "string",
              "Cofactor": "string",
              "GroupSize": "string",
              "Generator": "string",
              "GeneratorType": "string"
            },
            "key_size": "int"
          },
          "accepted_cipher_list": [
            {
              "ssl_version": "string",
              "is_anonymous": "boolean",
              "openssl_name": "string",
              "post_handshake_response": "string",
              "dh_info": {
                "Order": "string",
                "A": "string",
                "B": "string",
                "Type": "string",
                "Prime": "string",
                "Seed": "string",
                "Field_Type": "string",
                "Cofactor": "string",
                "GroupSize": "string",
                "Generator": "string",
                "GeneratorType": "string"
              },
              "key_size": "int"
            },
            ]
        },
        ...
      },
      "vulnerabilities": {
        "openssl_ccs": {
          "is_vulnerable_to_ccs_injection": "boolean"
        },
        "heartbleed": {
          "is_vulnerable_to_heartbleed": "boolean"
        },
        "renegotiation": {
          "accepts_client_renegotiation": "boolean",
          "supports_secure_renegotiation": "boolean"
        },
        "compression": {
          "supports_compression": "boolean",
          "compression_name": "string"
        },
        "fallback": {
          "supports_fallback_scsv": "boolean"
        },
        "robot": {
          "robot_result_enum": "string"
        }
      },
      "cert_info": {
        "ocsp_response": {},
        "ocsp_response_status": "string",
        "is_ocsp_response_trusted": "boolean",
        "certificate_has_must_staple_extension": "boolean",
        "certificate_included_scts_count": "int",
        "certificate_matches_hostname": "boolean",
        "is_certificate_chain_order_valid": "boolean",
        "has_anchor_in_certificate_chain": "boolean",
        "has_sha1_in_certificate_chain": "boolean",
        "is_leaf_certificate_ev": "boolean",
        "certificate_chain": [
          {
            "as_dict": {
              "extensions": {},
              "serial_number": "string",
              "subject": {
                "common_name": "string",
                "locality_name": "string",
                "organization_name": "string",
                "organizational_unit_name": "string",
                "country_name": "string",
                "state_or_province_name": "string"
              },
              "public_key_info": {
                "algorithm": "string",
                "key_size": "string",
                "modulus": "string",
                "exponent": "string",
                "curve": "string",
                "public_key": "string",
                "p": "string",
                "q": "string",
                "g": "string"
              },
              "validity": {
                "not_after": "string",
                "not_before": "string"
              },
              "version": "int",
              "issuer": {
                "common_name": "string",
                "locality_name": "string",
                "organizational_unit_name": "string",
                "organization_name": "string",
                "country_name": "string",
                "state_or_province_name": "string"
              },
              "signature_algorithm": "string",
              "signature_value": "string"
            },
            "sha1_fingerprint": "string",
            "sha256_fingerprint": "string",
            "hpkp_pin": "string",
            "crl_lookup_status": "boolean",
            "as_pem": "string"
          },
          ...
        ],
        "symantec_distrust_timeline" : "string",
        "verified_certificate_chain": [
          ...
        ],
        "successful_trust_store": {
          "version": "string",
          "name": "string"
        },
        "path_validation_result_list": [
          {
            "is_certificate_trusted": "boolean",
            "trust_store": {
              "name": "string",
              "version": "string"
            },
            "verify_string": "string"
          },
          ...
        ]
      },
      "server_info": {
        "openssl_cipher_string_supported": "string",
        "hostname": "string",
        "client_auth_requirement": "string",
        "highest_ssl_version_supported": "string",
        "port": "int",
        "http_tunneling_settings": {},
        "ip_address": "string",
        "client_auth_credentials": {},
        "tls_wrapped_protocol": "string",
        "xmpp_to_hostname": "string",
        "tls_server_name_indication": "string"
      }
    }
  },
  ...
}
```

### Contents of the fields:

* ciphers - the result of running a CipherSuiteScanCommand on a specific server. Note: independently of the type of cipher and cipher_list, they all have the same fields. So, in order to simplify, we will only describe one of each
  * sslv2 / sslv3 / tlsv1 / tlsv1_1 / tlsv1_2 / tlsv1_3 - versions of the ssl
    * errored_cipher_list - the list of cipher suites supported that triggered an unexpected error during the TLS handshake with the server
    * preferred_cipher - the server's preferred cipher suite among all the cipher suites supported, null if the server follows the client's preference or if none of the tool's cipher suites are supported by the server
    * accepted_cipher_list - the list of cipher suites supported by both the tool and the server
      * is_anonymous - true if the cipher suite is an anonymous cipher suite (ie. no server authentication)
      * openssl_name - the cipher suite's RFC name
      * post_handshake_response - the server's response after completing the SSL/TLS handshake and sending a request, based on the TlsWrappedProtocolEnum set for this server. For example, this will contain an HTTP response when scanning an HTTPS server with TlsWrappedProtocolEnum.HTTPS as the tls_wrapped_protocol
      * dh_info - additional details about the Diffie Helmann parameters for DH and ECDH cipher suites, null if the cipher suite is not DH or ECDH
      * key_size - the key size of the cipher suite's algorithm in bits
* vulnerabilities - information about SSL vulnerabilities
  * openssl_ccs - test the server(s) for the OpenSSL CCS injection vulnerability
    * is_vulnerable_to_ccs_injection - true if the server is vulnerable to OpenSSL's CCS injection issue
  * heartbleed - test the server(s) for the OpenSSL Heartbleed vulnerability
    * is_vulnerable_to_heartbleed - True if the server is vulnerable to the Heartbleed attack
  * renegotiation - test the server(s) for client-initiated renegotiation and secure renegotiation support
    * accepts_client_renegotiation - true if the server honors client-initiated renegotiation attempts
    * supports_secure_renegotiation - true if the server supports secure renegotiation
  * compression - test the server(s) for Zlib compression support
    * supports_compression - true if the server supports compression
    * compression_name - name of the compression used
  * fallback - test the server(s) for support of the TLS_FALLBACK_SCSV cipher suite which prevents downgrade attacks
    * supports_fallback_scsv - true if the server supports the TLS_FALLBACK_SCSV mechanism to block downgrade
  * robot - test the server(s) for the Return Of Bleichenbacher’s Oracle Threat vulnerability
    * robot_result_enum - an enum to provide the result of running a Robot Scan Command
* cert_info - verify the validity of the server(s) certificate(s) against various trust stores (Mozilla, Apple, etc.), and check for OCSP stapling support
  * ocsp_response - the OCSP response returned by the server, null if no response was sent by the server
  * ocsp_response_status - status of the OCSP response
  * is_ocsp_response_trusted - true if the OCSP response is trusted using the Mozilla trust store, null if no OCSP response was sent by the server
  * certificate_has_must_staple_extension - true if the leaf certificate has the OCSP Must-Staple extension as defined in RFC 6066
  * certificate_included_scts_count - the number of Signed Certificate Timestamps (SCTs) for Certificate Transparency embedded in the leaf certificate
  * certificate_matches_hostname - true if hostname validation was successful ie. the leaf certificate was issued for the server's hostname
  * has_anchor_in_certificate_chain - true if the server included the anchor/root certificate in the chain it send back to clients, null if the verified chain could not be built or no HPKP header was returned
  * has_sha1_in_certificate_chain - true if any of the leaf or intermediate certificates are signed using the SHA-1 algorithm, null if the verified chain could not be built or no HPKP header was returned
  * is_certificate_chain_order_valid - true if the order of the certificate chain is valid
  * is_leaf_certificate_ev - true if the leaf certificate is Extended Validation according to Mozilla
  * certificate_chain - the certificate chain sent by the server; index 0 is the leaf certificate
    * as_dict
      * extensions - contains the target's certificate extensions information
      * serial_number - the certificate serial number
      * subject - subject contains the target's certificate subject information
        * common_name - common name of the subject
        * locality_name - locality of the subject
        * organization_name - organization name of the subject
        * organizational_unit_name - organizational unit name of the subject
        * country_name - country of the subject
        * state_or_province_name - state or province of the subject
      * public_key_info - contains information about the public key stored in the certificate
        * algorithm - algorithm used to create the public key
        * key_size - size of the public key
        * modulus - returns the value of attribute modulus (RSA)
        * exponent - returns the value of attribute exponent (RSA)
        * curve - returns the curve used to create the public key (EC)
        * p - returns the value of attribute p (DSA)
        * q - returns the value of attribute q (DSA)
        * g - returns the value of attribute g (DSA)
        * public_key - contains the target public key (DSA,EC)
      * validity -  contains the target's certificate validity
        * not_after - expiration date of the certificate
        * not_before - date from which the certificate is valid
      * version - the certificate SSL version
      * issuer - contains the target's certificate issuer information
        * common_name - common name of the issuer
        * locality_name - locality of the issuer
        * organization_name - organization name of the issuer
        * organizational_unit_name - organizational name of the issuer
        * country_name - country of the issuer
        * state_or_province_name - stae or province of the issuer
      * signature_algorithm - the certificate signature algorithm
      * signature_value - the certificate signature
    * sha1_fingerprint - the SHA1 fingerprint of the certificate
    * sha256_fingerprint - the SHA256 fingerprint of the certificate
    * hpkp_pin - a generated HTTP Public Key Pinning hash for a given certificate (https://tools.ietf.org/html/rfc7469); not to be confused with an extracted HPKP header
    * crl_lookup_status - true if serial number of certificate was found on one of the CRL lists provided, false if not, null if there was an error performing the lookup
    * as_pem - the certificate in PEM format
  * symantec_distrust_timeline - when the certificate will be distrusted in Chrome and Firefox (https://blog.qualys.com/ssllabs/2017/09/26/google-and-mozilla-deprecating-existing-symantec-certificates), null if the certificate chain was not issued by one of the Symantec CAs
  * verified_certificate_chain - certificate chain after validation using the successful_trust_store; all the fields are the same as certificate_chain
  * successful_trust_store - the first trust store successfully used for validation; used afterwards to verify the certificate chain and the OSCP response
    * name - the human-readable name of the trust store
    * version - the human-readable version or date of the trust store
  * path_validation_result_list - the list of attempts at validating the server's certificate chain path using the trust stores packaged (Mozilla, Apple, etc.), the first element of this list becomes the value of successful_trust_store
    * is_certificate_trusted - whether the certificate chain is trusted when using supplied the trust_store
    * trust_store - the trust store used for validation
      * name - the human-readable name of the trust store
      * version - the human-readable version or date of the trust store
    * verify_string - the string returned by OpenSSL's validation function
* server_info - the server against which the command was run
  * openssl_cipher_string_supported - one of the ssl ciphers supported by the server
  * hostname - the server's hostname
  * client_auth_requirement - does the server require the client to be authenticated
  * highest_ssl_version_supported - the highest version of ssl supported for connections
  * port - the server's TLS port number. If not supplied, the default port number for the specified `tls_wrapped_protocol` will be used
  * http_tunneling_settings - settings defined for http tunnel
  * ip_address - the server's IP address. If not supplied, a DNS lookup for the specified `hostname` will be performed. If `http_tunneling_settings` is specified, `ip_address` cannot be supplied as the HTTP proxy will be responsible for looking up and connecting to the server to be scanned.
  * client_auth_credentials - The client certificate and private key needed to perform mutual authentication with the server. If not supplied, will attempt to connect to the server without performing mutual authentication
  * tls_wrapped_protocol - the protocol wrapped in TLS that the server expects. It allows to figure out how to establish a (Start)TLS connection to the server and what kind of "hello" message (SMTP, XMPP, etc.) to send to the server after the handshake was completed. If not supplied, standard TLS will be used.
  * xmpp_to_hostname - the hostname to set within the `to` attribute of the XMPP stream. If not supplied, the specified `hostname` will be used. Should only be set if the supplied `tls_wrapped_protocol` is an XMPP protocol
  * tls_server_name_indication - the hostname to set within the Server Name Indication TLS extension. If not supplied, the specified `hostname` will be used

## SSLv2 Event Example

### Request

```
curl https://api.binaryedge.io/v1/tasks -d '{"type":"scan", "description": "SSL Request", "options":[{"targets":["X.X.X.X"], "ports":[{"port":"443", "protocol":"tcp", "modules": ["sslv2"], "config":{"sni":"www.binaryedge.io", "ssl_mode":"full"}}]}]}' -H "X-Token:<Token>"
```

### Response

```json
{
  "result": {
    "data": {
      "cert_info": {
        "certificate_chain": [
          {
            "as_dict": {
              "extensions": {
                "authority_information_access": [
                  {
                    "access_location": "http://crt.comodoca4.com/COMODOECCDomainValidationSecureServerCA2.crt",
                    "access_method": "ca_issuers"
                  },
                  {
                    "access_location": "http://ocsp.comodoca4.com",
                    "access_method": "ocsp"
                  }
                ],
                "authority_key_identifier": {
                  "authority_cert_issuer": null,
                  "authority_cert_serial_number": null,
                  "key_identifier": "40:09:61:67:f0:bc:83:71:4f:de:12:08:2c:6f:d4:d4:2b:76:3d:96"
                },
                "basic_constraints": {
                  "ca": false,
                  "path_len_constraint": null
                },
                "certificate_policies": [
                  {
                    "policy_identifier": "1.3.6.1.4.1.6449.1.2.2.7",
                    "policy_qualifiers": [
                      {
                        "policy_qualifier_id": "certification_practice_statement",
                        "qualifier": "https://secure.comodo.com/CPS"
                      }
                    ]
                  },
                  {
                    "policy_identifier": "2.23.140.1.2.1",
                    "policy_qualifiers": null
                  }
                ],
                "crl_distribution_points": [
                  {
                    "crl_issuer": null,
                    "distribution_point": [
                      "http://crl.comodoca4.com/COMODOECCDomainValidationSecureServerCA2.crl"
                    ],
                    "reasons": null
                  }
                ],
                "extended_key_usage": [
                  "server_auth",
                  "client_auth"
                ],
                "key_identifier": "28:fb:87:9e:8d:f7:0b:f2:ad:2c:79:b7:f8:38:75:13:0b:de:0a:f0",
                "key_usage": [
                  "digital_signature"
                ],
                "signed_certificate_timestamp_list": [
                  {
                    "extensions": "",
                    "log_id": "ee:4b:bd:b7:75:ce:60:ba:e1:42:69:1f:ab:e1:9e:66:a3:0f:7e:5f:b0:72:d8:83:00:c4:7b:89:7a:a8:fd:cb",
                    "signature": "30:45:02:20:37:4c:2f:d9:8e:ce:e2:ea:13:eb:c7:7a:bd:0d:e1:4d:1a:7d:d8:7c:22:9b:a4:71:db:d2:4f:21:56:00:f4:bf:02:21:00:c5:5d:ef:e9:25:92:06:cd:8e:f5:aa:db:35:ea:8a:c0:52:67:2f:6a:d6:47:3a:79:d0:45:ff:4f:86:14:9f:83",
                    "signature_algorithm": "sha256_ecdsa",
                    "timestamp": "2018-08-09 01:21:12 GMT",
                    "version": "v1"
                  },
                  {
                    "extensions": "",
                    "log_id": "74:7e:da:83:31:ad:33:10:91:21:9c:ce:25:4f:42:70:c2:bf:fd:5e:42:20:08:c6:37:35:79:e6:10:7b:cc:56",
                    "signature": "30:44:02:20:52:76:ff:f9:cc:f8:86:43:ce:b8:4b:17:38:8a:68:7c:2c:3c:2c:66:a1:43:75:2a:46:a8:b6:bd:cb:f2:f2:2a:02:20:55:0c:b2:63:2c:a2:af:80:6c:8d:15:e9:1c:a0:9e:0f:9b:9b:53:ec:bb:69:1c:ff:4d:92:ad:76:59:16:8f:9c",
                    "signature_algorithm": "sha256_ecdsa",
                    "timestamp": "2018-08-09 01:21:12 GMT",
                    "version": "v1"
                  }
                ],
                "subject_alt_name": [
                  "sni177528.cloudflaressl.com",
                  "*.40fy.io",
                  "*.7starhotels.science",
                  "*.atls.to",
                  "*.binaryedge.io",
                  "*.boeyrtn.cf",
                  "*.cavingtour.trade",
                  "*.codeavenue.lk",
                  "*.content.school",
                  "*.corsectra.com",
                  "*.cozysleepoutdoor.com",
                  "*.deyvastators.gq",
                  "*.dmdveri.ru",
                  "*.getvenk.com",
                  "*.gizz143.tk",
                  "*.gyangangachhindwara.co.in",
                  "*.haphazardgourmet.ml",
                  "*.homeroom.school",
                  "*.hookedoncountry.ml",
                  "*.iismeucci.altervista.org",
                  "*.izse.cf",
                  "*.joyzone.co.za",
                  "*.lindehoek.nl",
                  "*.loagqnranch.ml",
                  "*.mllnybyhet.top",
                  "*.mofa.asia",
                  "*.nowans.com",
                  "*.pialejintu.top",
                  "*.pizzeria-alfredo-oberhausen.de",
                  "*.portcitysports.net",
                  "*.publisher.school",
                  "*.serieamonamour.com",
                  "*.sp-imports.com",
                  "*.splife.ru",
                  "*.terrjenals.ga",
                  "*.theshield.in",
                  "*.tlriehle.ml",
                  "*.troyshaw.ml",
                  "*.visitstlouis.com",
                  "*.vitamashoqts.gq",
                  "*.wordpowered.co.uk",
                  "*.wordpress-seo.co.uk",
                  "*.yauguarsookl.tk",
                  "*.yugo-gradnya.ru",
                  "*.zatopybohyyy.tk",
                  "40fy.io",
                  "7starhotels.science",
                  "atls.to",
                  "binaryedge.io",
                  "boeyrtn.cf",
                  "cavingtour.trade",
                  "codeavenue.lk",
                  "content.school",
                  "corsectra.com",
                  "cozysleepoutdoor.com",
                  "deyvastators.gq",
                  "dmdveri.ru",
                  "getvenk.com",
                  "gizz143.tk",
                  "gyangangachhindwara.co.in",
                  "haphazardgourmet.ml",
                  "homeroom.school",
                  "hookedoncountry.ml",
                  "iismeucci.altervista.org",
                  "izse.cf",
                  "joyzone.co.za",
                  "lindehoek.nl",
                  "loagqnranch.ml",
                  "mllnybyhet.top",
                  "mofa.asia",
                  "nowans.com",
                  "pialejintu.top",
                  "pizzeria-alfredo-oberhausen.de",
                  "portcitysports.net",
                  "publisher.school",
                  "serieamonamour.com",
                  "sp-imports.com",
                  "splife.ru",
                  "terrjenals.ga",
                  "theshield.in",
                  "tlriehle.ml",
                  "troyshaw.ml",
                  "visitstlouis.com",
                  "vitamashoqts.gq",
                  "wordpowered.co.uk",
                  "wordpress-seo.co.uk",
                  "yauguarsookl.tk",
                  "yugo-gradnya.ru",
                  "zatopybohyyy.tk"
                ]
              },
              "issuer": {
                "common_name": "COMODO ECC Domain Validation Secure Server CA 2",
                "country_name": "GB",
                "locality_name": "Salford",
                "organization_name": "COMODO CA Limited",
                "state_or_province_name": "Greater Manchester"
              },
              "public_key_info": {
                "algorithm": "ec",
                "curve": "secp256r1",
                "key_size": 256,
                "public_key": "04:e5:8e:6b:70:34:fb:ec:1f:30:78:56:64:04:ca:37:ff:7d:12:fc:55:e5:93:f3:c9:85:4c:0e:e4:40:23:e4:6f:20:c0:a5:7b:a9:9d:92:ea:a5:d7:63:ae:13:74:bc:57:88:60:01:d2:96:6c:15:30:33:b3:b8:ae:af:f8:17:ef"
              },
              "serial_number": "241279765222558670942807930801516531588",
              "signature_algorithm": "sha256_ecdsa",
              "signature_value": "30:46:02:21:00:e4:cc:2a:b3:a3:b2:54:37:1d:a2:be:2d:15:24:76:ea:02:31:ca:ff:b0:4a:12:48:a2:13:db:7c:2f:59:8d:74:02:21:00:99:8b:53:8d:2a:29:af:6d:f0:28:f9:fd:59:4d:15:6f:a3:5f:b1:62:8b:5f:42:a0:39:8b:a7:71:c6:79:98:3d",
              "subject": {
                "common_name": "sni177528.cloudflaressl.com",
                "organizational_unit_name": "Domain Control Validated | PositiveSSL Multi-Domain"
              },
              "validity": {
                "not_after": "2019-02-15 23:59:59 UTC+00:00",
                "not_before": "2018-08-09 00:00:00 UTC+00:00"
              },
              "version": "v3"
            },
            "as_pem": "-----BEGIN CERTIFICATE-----\nMIIK6zCCCpCgAwIBAgIRALWEyuAUZskCRdM7dII1T4QwCgYIKoZIzj0EAwIwgZIx\nCzAJBgNVBAYTAkdCMRswGQYDVQQIExJHcmVhdGVyIE1hbmNoZXN0ZXIxEDAOBgNV\nBAcTB1NhbGZvcmQxGjAYBgNVBAoTEUNPTU9ETyBDQSBMaW1pdGVkMTgwNgYDVQQD\nEy9DT01PRE8gRUNDIERvbWFpbiBWYWxpZGF0aW9uIFNlY3VyZSBTZXJ2ZXIgQ0Eg\nMjAeFw0xODA4MDkwMDAwMDBaFw0xOTAyMTUyMzU5NTlaMGwxITAfBgNVBAsTGERv\nbWFpbiBDb250cm9sIFZhbGlkYXRlZDEhMB8GA1UECxMYUG9zaXRpdmVTU0wgTXVs\ndGktRG9tYWluMSQwIgYDVQQDExtzbmkxNzc1MjguY2xvdWRmbGFyZXNzbC5jb20w\nWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATljmtwNPvsHzB4VmQEyjf/fRL8VeWT\n88mFTA7kQCPkbyDApXupnZLqpddjrhN0vFeIYAHSlmwVMDOzuK6v+Bfvo4II6jCC\nCOYwHwYDVR0jBBgwFoAUQAlhZ/C8g3FP3hIILG/U1Ct2PZYwHQYDVR0OBBYEFCj7\nh56N9wvyrSx5t/g4dRML3grwMA4GA1UdDwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAA\nMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjBPBgNVHSAESDBGMDoGCysG\nAQQBsjEBAgIHMCswKQYIKwYBBQUHAgEWHWh0dHBzOi8vc2VjdXJlLmNvbW9kby5j\nb20vQ1BTMAgGBmeBDAECATBWBgNVHR8ETzBNMEugSaBHhkVodHRwOi8vY3JsLmNv\nbW9kb2NhNC5jb20vQ09NT0RPRUNDRG9tYWluVmFsaWRhdGlvblNlY3VyZVNlcnZl\nckNBMi5jcmwwgYgGCCsGAQUFBwEBBHwwejBRBggrBgEFBQcwAoZFaHR0cDovL2Ny\ndC5jb21vZG9jYTQuY29tL0NPTU9ET0VDQ0RvbWFpblZhbGlkYXRpb25TZWN1cmVT\nZXJ2ZXJDQTIuY3J0MCUGCCsGAQUFBzABhhlodHRwOi8vb2NzcC5jb21vZG9jYTQu\nY29tMIIGKgYDVR0RBIIGITCCBh2CG3NuaTE3NzUyOC5jbG91ZGZsYXJlc3NsLmNv\nbYIJKi40MGZ5LmlvghUqLjdzdGFyaG90ZWxzLnNjaWVuY2WCCSouYXRscy50b4IP\nKi5iaW5hcnllZGdlLmlvggwqLmJvZXlydG4uY2aCEiouY2F2aW5ndG91ci50cmFk\nZYIPKi5jb2RlYXZlbnVlLmxrghAqLmNvbnRlbnQuc2Nob29sgg8qLmNvcnNlY3Ry\nYS5jb22CFiouY296eXNsZWVwb3V0ZG9vci5jb22CESouZGV5dmFzdGF0b3JzLmdx\nggwqLmRtZHZlcmkucnWCDSouZ2V0dmVuay5jb22CDCouZ2l6ejE0My50a4IbKi5n\neWFuZ2FuZ2FjaGhpbmR3YXJhLmNvLmlughUqLmhhcGhhemFyZGdvdXJtZXQubWyC\nESouaG9tZXJvb20uc2Nob29sghQqLmhvb2tlZG9uY291bnRyeS5tbIIaKi5paXNt\nZXVjY2kuYWx0ZXJ2aXN0YS5vcmeCCSouaXpzZS5jZoIPKi5qb3l6b25lLmNvLnph\ngg4qLmxpbmRlaG9lay5ubIIQKi5sb2FncW5yYW5jaC5tbIIQKi5tbGxueWJ5aGV0\nLnRvcIILKi5tb2ZhLmFzaWGCDCoubm93YW5zLmNvbYIQKi5waWFsZWppbnR1LnRv\ncIIgKi5waXp6ZXJpYS1hbGZyZWRvLW9iZXJoYXVzZW4uZGWCFCoucG9ydGNpdHlz\ncG9ydHMubmV0ghIqLnB1Ymxpc2hlci5zY2hvb2yCFCouc2VyaWVhbW9uYW1vdXIu\nY29tghAqLnNwLWltcG9ydHMuY29tggsqLnNwbGlmZS5ydYIPKi50ZXJyamVuYWxz\nLmdhgg4qLnRoZXNoaWVsZC5pboINKi50bHJpZWhsZS5tbIINKi50cm95c2hhdy5t\nbIISKi52aXNpdHN0bG91aXMuY29tghEqLnZpdGFtYXNob3F0cy5ncYITKi53b3Jk\ncG93ZXJlZC5jby51a4IVKi53b3JkcHJlc3Mtc2VvLmNvLnVrghEqLnlhdWd1YXJz\nb29rbC50a4IRKi55dWdvLWdyYWRueWEucnWCESouemF0b3B5Ym9oeXl5LnRrggc0\nMGZ5LmlvghM3c3RhcmhvdGVscy5zY2llbmNlggdhdGxzLnRvgg1iaW5hcnllZGdl\nLmlvggpib2V5cnRuLmNmghBjYXZpbmd0b3VyLnRyYWRlgg1jb2RlYXZlbnVlLmxr\ngg5jb250ZW50LnNjaG9vbIINY29yc2VjdHJhLmNvbYIUY296eXNsZWVwb3V0ZG9v\nci5jb22CD2RleXZhc3RhdG9ycy5ncYIKZG1kdmVyaS5ydYILZ2V0dmVuay5jb22C\nCmdpenoxNDMudGuCGWd5YW5nYW5nYWNoaGluZHdhcmEuY28uaW6CE2hhcGhhemFy\nZGdvdXJtZXQubWyCD2hvbWVyb29tLnNjaG9vbIISaG9va2Vkb25jb3VudHJ5Lm1s\nghhpaXNtZXVjY2kuYWx0ZXJ2aXN0YS5vcmeCB2l6c2UuY2aCDWpveXpvbmUuY28u\nemGCDGxpbmRlaG9lay5ubIIObG9hZ3FucmFuY2gubWyCDm1sbG55YnloZXQudG9w\nggltb2ZhLmFzaWGCCm5vd2Fucy5jb22CDnBpYWxlamludHUudG9wgh5waXp6ZXJp\nYS1hbGZyZWRvLW9iZXJoYXVzZW4uZGWCEnBvcnRjaXR5c3BvcnRzLm5ldIIQcHVi\nbGlzaGVyLnNjaG9vbIISc2VyaWVhbW9uYW1vdXIuY29tgg5zcC1pbXBvcnRzLmNv\nbYIJc3BsaWZlLnJ1gg10ZXJyamVuYWxzLmdhggx0aGVzaGllbGQuaW6CC3Rscmll\naGxlLm1sggt0cm95c2hhdy5tbIIQdmlzaXRzdGxvdWlzLmNvbYIPdml0YW1hc2hv\ncXRzLmdxghF3b3JkcG93ZXJlZC5jby51a4ITd29yZHByZXNzLXNlby5jby51a4IP\neWF1Z3VhcnNvb2tsLnRrgg95dWdvLWdyYWRueWEucnWCD3phdG9weWJvaHl5eS50\nazCCAQMGCisGAQQB1nkCBAIEgfQEgfEA7wB2AO5Lvbd1zmC64UJpH6vhnmajD35f\nsHLYgwDEe4l6qP3LAAABZRxF+rwAAAQDAEcwRQIgN0wv2Y7O4uoT68d6vQ3hTRp9\n2Hwim6Rx29JPIVYA9L8CIQDFXe/pJZIGzY71qts16orAUmcvatZHOnnQRf9PhhSf\ngwB1AHR+2oMxrTMQkSGcziVPQnDCv/1eQiAIxjc1eeYQe8xWAAABZRxF+wcAAAQD\nAEYwRAIgUnb/+cz4hkPOuEsXOIpofCw8LGahQ3UqRqi2vcvy8ioCIFUMsmMsoq+A\nbI0V6Rygng+bm1Psu2kc/02SrXZZFo+cMAoGCCqGSM49BAMCA0kAMEYCIQDkzCqz\no7JUNx2ivi0VJHbqAjHK/7BKEkiiE9t8L1mNdAIhAJmLU40qKa9t8Cj5/VlNFW+j\nX7Fii19CoDmLp3HGeZg9\n-----END CERTIFICATE-----\n",
            "crl_lookup_status": false,
            "hpkp_pin": "IaXoxGGXCD8qzLu92R1s2aiO/PlDP67OEEhBcdDLVKM=",
            "sha1_fingerprint": "77:EE:9D:F5:53:A6:E2:82:DA:0C:30:8F:0D:F3:B0:7D:67:AD:E1:81",
            "sha256_fingerprint": "53:ED:14:BF:25:44:50:33:F3:D7:89:F4:B6:D5:2A:E1:8A:75:B7:44:5F:4D:BD:06:16:2F:6A:C6:41:FD:DD:30"
          },
          {
            "as_dict": {
              "extensions": {
                "authority_information_access": [
                  {
                    "access_location": "http://crt.comodoca.com/COMODOECCAddTrustCA.crt",
                    "access_method": "ca_issuers"
                  },
                  {
                    "access_location": "http://ocsp.comodoca4.com",
                    "access_method": "ocsp"
                  }
                ],
                "authority_key_identifier": {
                  "authority_cert_issuer": null,
                  "authority_cert_serial_number": null,
                  "key_identifier": "75:71:a7:19:48:19:bc:9d:9d:ea:41:47:df:94:c4:48:77:99:d3:79"
                },
                "basic_constraints": {
                  "ca": true,
                  "path_len_constraint": 0
                },
                "certificate_policies": [
                  {
                    "policy_identifier": "any_policy",
                    "policy_qualifiers": null
                  },
                  {
                    "policy_identifier": "2.23.140.1.2.1",
                    "policy_qualifiers": null
                  }
                ],
                "crl_distribution_points": [
                  {
                    "crl_issuer": null,
                    "distribution_point": [
                      "http://crl.comodoca.com/COMODOECCCertificationAuthority.crl"
                    ],
                    "reasons": null
                  }
                ],
                "extended_key_usage": [
                  "server_auth",
                  "client_auth"
                ],
                "key_identifier": "40:09:61:67:f0:bc:83:71:4f:de:12:08:2c:6f:d4:d4:2b:76:3d:96",
                "key_usage": [
                  "digital_signature",
                  "key_cert_sign",
                  "crl_sign"
                ]
              },
              "issuer": {
                "common_name": "COMODO ECC Certification Authority",
                "country_name": "GB",
                "locality_name": "Salford",
                "organization_name": "COMODO CA Limited",
                "state_or_province_name": "Greater Manchester"
              },
              "public_key": {
                "algorithm": "ec",
                "curve": "secp256r1",
                "key_size": 256,
                "public_key": "04:02:38:19:81:3a:c9:69:84:70:59:02:8e:a8:8a:1f:30:df:bc:de:03:fc:79:1d:3a:25:2c:6b:41:21:18:82:ea:f9:3e:4a:e4:33:cc:12:cf:2a:43:fc:0e:f2:64:00:c0:e1:25:50:82:24:cd:b6:49:38:0f:25:47:91:48:a4:ad"
              },
              "serial_number": "121156049097932074853067657954953090221",
              "signature_algorithm": "sha384_ecdsa",
              "signature_value": "30:65:02:31:00:ac:68:47:25:80:13:4f:13:56:c0:a2:37:09:97:5a:50:c4:e7:ed:b4:61:cb:28:8a:0a:11:32:a6:e2:71:df:11:01:89:6f:07:7a:20:66:6b:18:d0:b9:2e:43:f7:52:6f:02:30:12:85:7c:8e:13:66:92:04:ba:9a:45:09:94:4a:30:61:d1:49:dc:6f:eb:e7:2d:c9:89:cf:1e:6a:7c:ec:85:ce:30:25:59:ba:81:70:34:b8:34:7f:e7:01:d1:e2:cb:52",
              "subject": {
                "common_name": "COMODO ECC Domain Validation Secure Server CA 2",
                "country_name": "GB",
                "locality_name": "Salford",
                "organization_name": "COMODO CA Limited",
                "state_or_province_name": "Greater Manchester"
              },
              "validity": {
                "not_after": "2029-09-24 23:59:59 UTC+00:00",
                "not_before": "2014-09-25 00:00:00 UTC+00:00"
              },
              "version": "v3"
            },
            "as_pem": "-----BEGIN CERTIFICATE-----\nMIIDnzCCAyWgAwIBAgIQWyXOaQfEJlVm0zkMmalUrTAKBggqhkjOPQQDAzCBhTEL\nMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UE\nBxMHU2FsZm9yZDEaMBgGA1UEChMRQ09NT0RPIENBIExpbWl0ZWQxKzApBgNVBAMT\nIkNPTU9ETyBFQ0MgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMTQwOTI1MDAw\nMDAwWhcNMjkwOTI0MjM1OTU5WjCBkjELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdy\nZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UEBxMHU2FsZm9yZDEaMBgGA1UEChMRQ09N\nT0RPIENBIExpbWl0ZWQxODA2BgNVBAMTL0NPTU9ETyBFQ0MgRG9tYWluIFZhbGlk\nYXRpb24gU2VjdXJlIFNlcnZlciBDQSAyMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcD\nQgAEAjgZgTrJaYRwWQKOqIofMN+83gP8eR06JSxrQSEYgur5PkrkM8wSzypD/A7y\nZADA4SVQgiTNtkk4DyVHkUikraOCAWYwggFiMB8GA1UdIwQYMBaAFHVxpxlIGbyd\nnepBR9+UxEh3mdN5MB0GA1UdDgQWBBRACWFn8LyDcU/eEggsb9TUK3Y9ljAOBgNV\nHQ8BAf8EBAMCAYYwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHSUEFjAUBggrBgEF\nBQcDAQYIKwYBBQUHAwIwGwYDVR0gBBQwEjAGBgRVHSAAMAgGBmeBDAECATBMBgNV\nHR8ERTBDMEGgP6A9hjtodHRwOi8vY3JsLmNvbW9kb2NhLmNvbS9DT01PRE9FQ0ND\nZXJ0aWZpY2F0aW9uQXV0aG9yaXR5LmNybDByBggrBgEFBQcBAQRmMGQwOwYIKwYB\nBQUHMAKGL2h0dHA6Ly9jcnQuY29tb2RvY2EuY29tL0NPTU9ET0VDQ0FkZFRydXN0\nQ0EuY3J0MCUGCCsGAQUFBzABhhlodHRwOi8vb2NzcC5jb21vZG9jYTQuY29tMAoG\nCCqGSM49BAMDA2gAMGUCMQCsaEclgBNPE1bAojcJl1pQxOfttGHLKIoKETKm4nHf\nEQGJbwd6IGZrGNC5LkP3Um8CMBKFfI4TZpIEuppFCZRKMGHRSdxv6+ctyYnPHmp8\n7IXOMCVZuoFwNLg0f+cB0eLLUg==\n-----END CERTIFICATE-----\n",
            "crl_lookup_status": null,
            "hpkp_pin": "x9SZw6TwIqfmvrLZ/kz1o0Ossjmn728BnBKpUFqGNVM=",
            "sha1_fingerprint": "75:CF:D9:BC:5C:EF:A1:04:EC:C1:08:2D:77:E6:33:92:CC:BA:52:91",
            "sha256_fingerprint": "CD:6C:10:8A:0E:64:1F:2C:A1:22:AA:A6:D0:3F:82:67:59:CA:E7:C6:F8:00:EA:BF:76:DC:48:B6:7C:D0:83:CE"
          },
          {
            "as_dict": {
              "extensions": {
                "authority_information_access": [
                  {
                    "access_location": "http://ocsp.trust-provider.com",
                    "access_method": "ocsp"
                  }
                ],
                "authority_key_identifier": {
                  "authority_cert_issuer": null,
                  "authority_cert_serial_number": null,
                  "key_identifier": "ad:bd:98:7a:34:b4:26:f7:fa:c4:26:54:ef:03:bd:e0:24:cb:54:1a"
                },
                "basic_constraints": {
                  "ca": true,
                  "path_len_constraint": null
                },
                "certificate_policies": [
                  {
                    "policy_identifier": "any_policy",
                    "policy_qualifiers": null
                  }
                ],
                "crl_distribution_points": [
                  {
                    "crl_issuer": null,
                    "distribution_point": [
                      "http://crl.trust-provider.com/AddTrustExternalCARoot.crl"
                    ],
                    "reasons": null
                  }
                ],
                "key_identifier": "75:71:a7:19:48:19:bc:9d:9d:ea:41:47:df:94:c4:48:77:99:d3:79",
                "key_usage": [
                  "digital_signature",
                  "key_cert_sign",
                  "crl_sign"
                ]
              },
              "issuer": {
                "common_name": "AddTrust External CA Root",
                "country_name": "SE",
                "organization_name": "AddTrust AB",
                "organizational_unit_name": "AddTrust External TTP Network"
              },
              "public_key": {
                "algorithm": "ec",
                "curve": "secp384r1",
                "key_size": 384,
                "public_key": "04:03:47:7b:2f:75:c9:82:15:85:fb:75:e4:91:16:d4:ab:62:99:f5:3e:52:0b:06:ce:41:00:7f:97:e1:0a:24:3c:1d:01:04:ee:3d:d2:8d:09:97:0c:e0:75:e4:fa:fb:77:8a:2a:f5:03:60:4b:36:8b:16:23:16:ad:09:71:f4:4a:f4:28:50:b4:fe:88:1c:6e:3f:6c:2f:2f:09:59:5b:a5:5b:0b:33:99:e2:c3:3d:89:f9:6a:2c:ef:b2:d3:06:e9"
              },
              "serial_number": "89484089693757697639156913870987150414",
              "signature_algorithm": "sha384_rsa",
              "signature_value": "1d:c7:fa:2e:40:b6:5c:05:4b:0f:bc:55:36:01:58:e0:53:05:3d:64:fb:ac:d9:a5:38:b8:a7:21:3b:af:95:5b:be:48:c8:d3:43:d4:21:6c:41:ed:09:2d:9c:73:00:71:9c:ae:21:73:7e:ff:8e:8d:b9:8e:58:90:8e:fc:8c:6d:76:c8:00:3a:9f:20:a6:2d:7d:cc:17:fd:cd:98:96:32:09:1a:c9:65:fc:04:eb:b4:9a:0a:78:e5:97:3b:52:8f:12:c2:74:97:01:9e:cf:e1:6d:68:d8:93:b9:9c:24:fb:96:27:48:01:9c:ea:94:3f:70:98:41:b3:73:51:37:29:e8:f6:01:7a:b9:27:b8:24:51:d9:11:68:d4:a6:85:a7:36:a7:a5:96:ba:80:f8:a6:fd:ae:6d:84:20:ae:35:76:73:42:0f:87:09:ec:c5:dc:e7:93:03:22:1a:97:ee:9a:8a:51:61:a7:97:26:1e:e9:ee:75:51:08:90:05:af:2f:9e:13:9c:93:3f:7a:ff:e6:eb:e9:68:79:8c:af:e0:b6:fa:ee:9b:12:13:fe:45:8c:d2:7c:d3:35:eb:21:12:93:fe:66:75:26:2a:15:84:26:f7:66:c9:cb:8d:bb:09:41:d4:18:af:b1:b3:10:f5:10:ca:9d:9a:0e:b5:75:6a:e8",
              "subject": {
                "common_name": "COMODO ECC Certification Authority",
                "country_name": "GB",
                "locality_name": "Salford",
                "organization_name": "COMODO CA Limited",
                "state_or_province_name": "Greater Manchester"
              },
              "validity": {
                "not_after": "2020-05-30 10:48:38 UTC+00:00",
                "not_before": "2000-05-30 10:48:38 UTC+00:00"
              },
              "version": "v3"
            },
            "as_pem": "-----BEGIN CERTIFICATE-----\nMIID0DCCArigAwIBAgIQQ1ICP/qokB8Tn+P05cFETjANBgkqhkiG9w0BAQwFADBv\nMQswCQYDVQQGEwJTRTEUMBIGA1UEChMLQWRkVHJ1c3QgQUIxJjAkBgNVBAsTHUFk\nZFRydXN0IEV4dGVybmFsIFRUUCBOZXR3b3JrMSIwIAYDVQQDExlBZGRUcnVzdCBF\neHRlcm5hbCBDQSBSb290MB4XDTAwMDUzMDEwNDgzOFoXDTIwMDUzMDEwNDgzOFow\ngYUxCzAJBgNVBAYTAkdCMRswGQYDVQQIExJHcmVhdGVyIE1hbmNoZXN0ZXIxEDAO\nBgNVBAcTB1NhbGZvcmQxGjAYBgNVBAoTEUNPTU9ETyBDQSBMaW1pdGVkMSswKQYD\nVQQDEyJDT01PRE8gRUNDIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MHYwEAYHKoZI\nzj0CAQYFK4EEACIDYgAEA0d7L3XJghWF+3XkkRbUq2KZ9T5SCwbOQQB/l+EKJDwd\nAQTuPdKNCZcM4HXk+vt3iir1A2BLNosWIxatCXH0SvQoULT+iBxuP2wvLwlZW6Vb\nCzOZ4sM9iflqLO+y0wbpo4H+MIH7MB8GA1UdIwQYMBaAFK29mHo0tCb3+sQmVO8D\nveAky1QaMB0GA1UdDgQWBBR1cacZSBm8nZ3qQUfflMRId5nTeTAOBgNVHQ8BAf8E\nBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zARBgNVHSAECjAIMAYGBFUdIAAwSQYDVR0f\nBEIwQDA+oDygOoY4aHR0cDovL2NybC50cnVzdC1wcm92aWRlci5jb20vQWRkVHJ1\nc3RFeHRlcm5hbENBUm9vdC5jcmwwOgYIKwYBBQUHAQEELjAsMCoGCCsGAQUFBzAB\nhh5odHRwOi8vb2NzcC50cnVzdC1wcm92aWRlci5jb20wDQYJKoZIhvcNAQEMBQAD\nggEBAB3H+i5AtlwFSw+8VTYBWOBTBT1k+6zZpTi4pyE7r5VbvkjI00PUIWxB7Qkt\nnHMAcZyuIXN+/46NuY5YkI78jG12yAA6nyCmLX3MF/3NmJYyCRrJZfwE67SaCnjl\nlztSjxLCdJcBns/hbWjYk7mcJPuWJ0gBnOqUP3CYQbNzUTcp6PYBerknuCRR2RFo\n1KaFpzanpZa6gPim/a5thCCuNXZzQg+HCezF3OeTAyIal+6ailFhp5cmHunudVEI\nkAWvL54TnJM/ev/m6+loeYyv4Lb67psSE/5FjNJ80zXrIRKT/mZ1JioVhCb3ZsnL\njbsJQdQYr7GzEPUQyp2aDrV1aug=\n-----END CERTIFICATE-----\n",
            "crl_lookup_status": false,
            "hpkp_pin": "58qRu/uxh4gFezqAcERupSkRYBlBAvfcw7mEjGPLnNU=",
            "sha1_fingerprint": "AE:22:3C:BF:20:19:1B:40:D7:FF:B4:EA:57:01:B6:5F:DC:68:A1:CA",
            "sha256_fingerprint": "95:73:86:2A:C0:B4:B1:25:16:88:10:EA:3F:D1:01:AE:2E:B0:BB:15:F6:1F:C0:E6:DA:7A:2A:38:B8:5A:89:E8"
          }
        ],
        "certificate_has_must_staple_extension": false,
        "certificate_included_scts_count": 2,
        "certificate_matches_hostname": true,
        "has_anchor_in_certificate_chain": false,
        "has_sha1_in_certificate_chain": false,
        "is_certificate_chain_order_valid": true,
        "is_leaf_certificate_ev": false,
        "is_ocsp_response_trusted": true,
        "ocsp_response": {
          "producedAt": "Aug 11 18:43:54 2018 GMT",
          "responderID": "40096167F0BC83714FDE12082C6FD4D42B763D96",
          "responseStatus": "successful",
          "responseType": "Basic OCSP Response",
          "responses": [
            {
              "certID": {
                "hashAlgorithm": "sha1",
                "issuerKeyHash": "40096167F0BC83714FDE12082C6FD4D42B763D96",
                "issuerNameHash": "CEA633847FA2C6D73E768EA031C03953C6868E0A",
                "serialNumber": "B584CAE01466C90245D33B7482354F84"
              },
              "certStatus": "good",
              "nextUpdate": "Aug 18 18:43:54 2018 GMT",
              "thisUpdate": "Aug 11 18:43:54 2018 GMT"
            }
          ],
          "version": "1"
        },
        "ocsp_response_status": "SUCCESSFUL",
        "path_validation_result_list": [
          {
            "is_certificate_trusted": true,
            "trust_store": {
              "name": "Android",
              "version": "8.1.0_r9"
            },
            "verify_string": "ok"
          },
          {
            "is_certificate_trusted": true,
            "trust_store": {
              "name": "iOS",
              "version": "11"
            },
            "verify_string": "ok"
          },
          {
            "is_certificate_trusted": true,
            "trust_store": {
              "name": "Java",
              "version": "jre-10.0.1"
            },
            "verify_string": "ok"
          },
          {
            "is_certificate_trusted": true,
            "trust_store": {
              "name": "macOS",
              "version": "High Sierra"
            },
            "verify_string": "ok"
          },
          {
            "is_certificate_trusted": true,
            "trust_store": {
              "name": "Mozilla",
              "version": "2018-04-12"
            },
            "verify_string": "ok"
          },
          {
            "is_certificate_trusted": true,
            "trust_store": {
              "name": "Windows",
              "version": "2018-04-26"
            },
            "verify_string": "ok"
          }
        ],
        "successful_trust_store": {
          "name": "Windows",
          "version": "2018-04-26"
        },
        "symantec_distrust_timeline": null,
        "verified_certificate_chain": [
          {
            "as_dict": {
              "extensions": {
                "authority_information_access": [
                  {
                    "access_location": "http://crt.comodoca4.com/COMODOECCDomainValidationSecureServerCA2.crt",
                    "access_method": "ca_issuers"
                  },
                  {
                    "access_location": "http://ocsp.comodoca4.com",
                    "access_method": "ocsp"
                  }
                ],
                "authority_key_identifier": {
                  "authority_cert_issuer": null,
                  "authority_cert_serial_number": null,
                  "key_identifier": "40:09:61:67:f0:bc:83:71:4f:de:12:08:2c:6f:d4:d4:2b:76:3d:96"
                },
                "basic_constraints": {
                  "ca": false,
                  "path_len_constraint": null
                },
                "certificate_policies": [
                  {
                    "policy_identifier": "1.3.6.1.4.1.6449.1.2.2.7",
                    "policy_qualifiers": [
                      {
                        "policy_qualifier_id": "certification_practice_statement",
                        "qualifier": "https://secure.comodo.com/CPS"
                      }
                    ]
                  },
                  {
                    "policy_identifier": "2.23.140.1.2.1",
                    "policy_qualifiers": null
                  }
                ],
                "crl_distribution_points": [
                  {
                    "crl_issuer": null,
                    "distribution_point": [
                      "http://crl.comodoca4.com/COMODOECCDomainValidationSecureServerCA2.crl"
                    ],
                    "reasons": null
                  }
                ],
                "extended_key_usage": [
                  "server_auth",
                  "client_auth"
                ],
                "key_identifier": "28:fb:87:9e:8d:f7:0b:f2:ad:2c:79:b7:f8:38:75:13:0b:de:0a:f0",
                "key_usage": [
                  "digital_signature"
                ],
                "signed_certificate_timestamp_list": [
                  {
                    "extensions": "",
                    "log_id": "ee:4b:bd:b7:75:ce:60:ba:e1:42:69:1f:ab:e1:9e:66:a3:0f:7e:5f:b0:72:d8:83:00:c4:7b:89:7a:a8:fd:cb",
                    "signature": "30:45:02:20:37:4c:2f:d9:8e:ce:e2:ea:13:eb:c7:7a:bd:0d:e1:4d:1a:7d:d8:7c:22:9b:a4:71:db:d2:4f:21:56:00:f4:bf:02:21:00:c5:5d:ef:e9:25:92:06:cd:8e:f5:aa:db:35:ea:8a:c0:52:67:2f:6a:d6:47:3a:79:d0:45:ff:4f:86:14:9f:83",
                    "signature_algorithm": "sha256_ecdsa",
                    "timestamp": "2018-08-09 01:21:12 GMT",
                    "version": "v1"
                  },
                  {
                    "extensions": "",
                    "log_id": "74:7e:da:83:31:ad:33:10:91:21:9c:ce:25:4f:42:70:c2:bf:fd:5e:42:20:08:c6:37:35:79:e6:10:7b:cc:56",
                    "signature": "30:44:02:20:52:76:ff:f9:cc:f8:86:43:ce:b8:4b:17:38:8a:68:7c:2c:3c:2c:66:a1:43:75:2a:46:a8:b6:bd:cb:f2:f2:2a:02:20:55:0c:b2:63:2c:a2:af:80:6c:8d:15:e9:1c:a0:9e:0f:9b:9b:53:ec:bb:69:1c:ff:4d:92:ad:76:59:16:8f:9c",
                    "signature_algorithm": "sha256_ecdsa",
                    "timestamp": "2018-08-09 01:21:12 GMT",
                    "version": "v1"
                  }
                ],
                "subject_alt_name": [
                  "sni177528.cloudflaressl.com",
                  "*.40fy.io",
                  "*.7starhotels.science",
                  "*.atls.to",
                  "*.binaryedge.io",
                  "*.boeyrtn.cf",
                  "*.cavingtour.trade",
                  "*.codeavenue.lk",
                  "*.content.school",
                  "*.corsectra.com",
                  "*.cozysleepoutdoor.com",
                  "*.deyvastators.gq",
                  "*.dmdveri.ru",
                  "*.getvenk.com",
                  "*.gizz143.tk",
                  "*.gyangangachhindwara.co.in",
                  "*.haphazardgourmet.ml",
                  "*.homeroom.school",
                  "*.hookedoncountry.ml",
                  "*.iismeucci.altervista.org",
                  "*.izse.cf",
                  "*.joyzone.co.za",
                  "*.lindehoek.nl",
                  "*.loagqnranch.ml",
                  "*.mllnybyhet.top",
                  "*.mofa.asia",
                  "*.nowans.com",
                  "*.pialejintu.top",
                  "*.pizzeria-alfredo-oberhausen.de",
                  "*.portcitysports.net",
                  "*.publisher.school",
                  "*.serieamonamour.com",
                  "*.sp-imports.com",
                  "*.splife.ru",
                  "*.terrjenals.ga",
                  "*.theshield.in",
                  "*.tlriehle.ml",
                  "*.troyshaw.ml",
                  "*.visitstlouis.com",
                  "*.vitamashoqts.gq",
                  "*.wordpowered.co.uk",
                  "*.wordpress-seo.co.uk",
                  "*.yauguarsookl.tk",
                  "*.yugo-gradnya.ru",
                  "*.zatopybohyyy.tk",
                  "40fy.io",
                  "7starhotels.science",
                  "atls.to",
                  "binaryedge.io",
                  "boeyrtn.cf",
                  "cavingtour.trade",
                  "codeavenue.lk",
                  "content.school",
                  "corsectra.com",
                  "cozysleepoutdoor.com",
                  "deyvastators.gq",
                  "dmdveri.ru",
                  "getvenk.com",
                  "gizz143.tk",
                  "gyangangachhindwara.co.in",
                  "haphazardgourmet.ml",
                  "homeroom.school",
                  "hookedoncountry.ml",
                  "iismeucci.altervista.org",
                  "izse.cf",
                  "joyzone.co.za",
                  "lindehoek.nl",
                  "loagqnranch.ml",
                  "mllnybyhet.top",
                  "mofa.asia",
                  "nowans.com",
                  "pialejintu.top",
                  "pizzeria-alfredo-oberhausen.de",
                  "portcitysports.net",
                  "publisher.school",
                  "serieamonamour.com",
                  "sp-imports.com",
                  "splife.ru",
                  "terrjenals.ga",
                  "theshield.in",
                  "tlriehle.ml",
                  "troyshaw.ml",
                  "visitstlouis.com",
                  "vitamashoqts.gq",
                  "wordpowered.co.uk",
                  "wordpress-seo.co.uk",
                  "yauguarsookl.tk",
                  "yugo-gradnya.ru",
                  "zatopybohyyy.tk"
                ]
              },
              "issuer": {
                "common_name": "COMODO ECC Domain Validation Secure Server CA 2",
                "country_name": "GB",
                "locality_name": "Salford",
                "organization_name": "COMODO CA Limited",
                "state_or_province_name": "Greater Manchester"
              },
              "public_key": {
                "algorithm": "ec",
                "curve": "secp256r1",
                "key_size": 256,
                "public_key": "04:e5:8e:6b:70:34:fb:ec:1f:30:78:56:64:04:ca:37:ff:7d:12:fc:55:e5:93:f3:c9:85:4c:0e:e4:40:23:e4:6f:20:c0:a5:7b:a9:9d:92:ea:a5:d7:63:ae:13:74:bc:57:88:60:01:d2:96:6c:15:30:33:b3:b8:ae:af:f8:17:ef"
              },
              "serial_number": "241279765222558670942807930801516531588",
              "signature_algorithm": "sha256_ecdsa",
              "signature_value": "30:46:02:21:00:e4:cc:2a:b3:a3:b2:54:37:1d:a2:be:2d:15:24:76:ea:02:31:ca:ff:b0:4a:12:48:a2:13:db:7c:2f:59:8d:74:02:21:00:99:8b:53:8d:2a:29:af:6d:f0:28:f9:fd:59:4d:15:6f:a3:5f:b1:62:8b:5f:42:a0:39:8b:a7:71:c6:79:98:3d",
              "subject": {
                "common_name": "sni177528.cloudflaressl.com",
                "organizational_unit_name": "Domain Control Validated | PositiveSSL Multi-Domain"
              },
              "validity": {
                "not_after": "2019-02-15 23:59:59 UTC+00:00",
                "not_before": "2018-08-09 00:00:00 UTC+00:00"
              },
              "version": "v3"
            },
            "as_pem": "-----BEGIN CERTIFICATE-----\nMIIK6zCCCpCgAwIBAgIRALWEyuAUZskCRdM7dII1T4QwCgYIKoZIzj0EAwIwgZIx\nCzAJBgNVBAYTAkdCMRswGQYDVQQIExJHcmVhdGVyIE1hbmNoZXN0ZXIxEDAOBgNV\nBAcTB1NhbGZvcmQxGjAYBgNVBAoTEUNPTU9ETyBDQSBMaW1pdGVkMTgwNgYDVQQD\nEy9DT01PRE8gRUNDIERvbWFpbiBWYWxpZGF0aW9uIFNlY3VyZSBTZXJ2ZXIgQ0Eg\nMjAeFw0xODA4MDkwMDAwMDBaFw0xOTAyMTUyMzU5NTlaMGwxITAfBgNVBAsTGERv\nbWFpbiBDb250cm9sIFZhbGlkYXRlZDEhMB8GA1UECxMYUG9zaXRpdmVTU0wgTXVs\ndGktRG9tYWluMSQwIgYDVQQDExtzbmkxNzc1MjguY2xvdWRmbGFyZXNzbC5jb20w\nWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATljmtwNPvsHzB4VmQEyjf/fRL8VeWT\n88mFTA7kQCPkbyDApXupnZLqpddjrhN0vFeIYAHSlmwVMDOzuK6v+Bfvo4II6jCC\nCOYwHwYDVR0jBBgwFoAUQAlhZ/C8g3FP3hIILG/U1Ct2PZYwHQYDVR0OBBYEFCj7\nh56N9wvyrSx5t/g4dRML3grwMA4GA1UdDwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAA\nMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjBPBgNVHSAESDBGMDoGCysG\nAQQBsjEBAgIHMCswKQYIKwYBBQUHAgEWHWh0dHBzOi8vc2VjdXJlLmNvbW9kby5j\nb20vQ1BTMAgGBmeBDAECATBWBgNVHR8ETzBNMEugSaBHhkVodHRwOi8vY3JsLmNv\nbW9kb2NhNC5jb20vQ09NT0RPRUNDRG9tYWluVmFsaWRhdGlvblNlY3VyZVNlcnZl\nckNBMi5jcmwwgYgGCCsGAQUFBwEBBHwwejBRBggrBgEFBQcwAoZFaHR0cDovL2Ny\ndC5jb21vZG9jYTQuY29tL0NPTU9ET0VDQ0RvbWFpblZhbGlkYXRpb25TZWN1cmVT\nZXJ2ZXJDQTIuY3J0MCUGCCsGAQUFBzABhhlodHRwOi8vb2NzcC5jb21vZG9jYTQu\nY29tMIIGKgYDVR0RBIIGITCCBh2CG3NuaTE3NzUyOC5jbG91ZGZsYXJlc3NsLmNv\nbYIJKi40MGZ5LmlvghUqLjdzdGFyaG90ZWxzLnNjaWVuY2WCCSouYXRscy50b4IP\nKi5iaW5hcnllZGdlLmlvggwqLmJvZXlydG4uY2aCEiouY2F2aW5ndG91ci50cmFk\nZYIPKi5jb2RlYXZlbnVlLmxrghAqLmNvbnRlbnQuc2Nob29sgg8qLmNvcnNlY3Ry\nYS5jb22CFiouY296eXNsZWVwb3V0ZG9vci5jb22CESouZGV5dmFzdGF0b3JzLmdx\nggwqLmRtZHZlcmkucnWCDSouZ2V0dmVuay5jb22CDCouZ2l6ejE0My50a4IbKi5n\neWFuZ2FuZ2FjaGhpbmR3YXJhLmNvLmlughUqLmhhcGhhemFyZGdvdXJtZXQubWyC\nESouaG9tZXJvb20uc2Nob29sghQqLmhvb2tlZG9uY291bnRyeS5tbIIaKi5paXNt\nZXVjY2kuYWx0ZXJ2aXN0YS5vcmeCCSouaXpzZS5jZoIPKi5qb3l6b25lLmNvLnph\ngg4qLmxpbmRlaG9lay5ubIIQKi5sb2FncW5yYW5jaC5tbIIQKi5tbGxueWJ5aGV0\nLnRvcIILKi5tb2ZhLmFzaWGCDCoubm93YW5zLmNvbYIQKi5waWFsZWppbnR1LnRv\ncIIgKi5waXp6ZXJpYS1hbGZyZWRvLW9iZXJoYXVzZW4uZGWCFCoucG9ydGNpdHlz\ncG9ydHMubmV0ghIqLnB1Ymxpc2hlci5zY2hvb2yCFCouc2VyaWVhbW9uYW1vdXIu\nY29tghAqLnNwLWltcG9ydHMuY29tggsqLnNwbGlmZS5ydYIPKi50ZXJyamVuYWxz\nLmdhgg4qLnRoZXNoaWVsZC5pboINKi50bHJpZWhsZS5tbIINKi50cm95c2hhdy5t\nbIISKi52aXNpdHN0bG91aXMuY29tghEqLnZpdGFtYXNob3F0cy5ncYITKi53b3Jk\ncG93ZXJlZC5jby51a4IVKi53b3JkcHJlc3Mtc2VvLmNvLnVrghEqLnlhdWd1YXJz\nb29rbC50a4IRKi55dWdvLWdyYWRueWEucnWCESouemF0b3B5Ym9oeXl5LnRrggc0\nMGZ5LmlvghM3c3RhcmhvdGVscy5zY2llbmNlggdhdGxzLnRvgg1iaW5hcnllZGdl\nLmlvggpib2V5cnRuLmNmghBjYXZpbmd0b3VyLnRyYWRlgg1jb2RlYXZlbnVlLmxr\ngg5jb250ZW50LnNjaG9vbIINY29yc2VjdHJhLmNvbYIUY296eXNsZWVwb3V0ZG9v\nci5jb22CD2RleXZhc3RhdG9ycy5ncYIKZG1kdmVyaS5ydYILZ2V0dmVuay5jb22C\nCmdpenoxNDMudGuCGWd5YW5nYW5nYWNoaGluZHdhcmEuY28uaW6CE2hhcGhhemFy\nZGdvdXJtZXQubWyCD2hvbWVyb29tLnNjaG9vbIISaG9va2Vkb25jb3VudHJ5Lm1s\nghhpaXNtZXVjY2kuYWx0ZXJ2aXN0YS5vcmeCB2l6c2UuY2aCDWpveXpvbmUuY28u\nemGCDGxpbmRlaG9lay5ubIIObG9hZ3FucmFuY2gubWyCDm1sbG55YnloZXQudG9w\nggltb2ZhLmFzaWGCCm5vd2Fucy5jb22CDnBpYWxlamludHUudG9wgh5waXp6ZXJp\nYS1hbGZyZWRvLW9iZXJoYXVzZW4uZGWCEnBvcnRjaXR5c3BvcnRzLm5ldIIQcHVi\nbGlzaGVyLnNjaG9vbIISc2VyaWVhbW9uYW1vdXIuY29tgg5zcC1pbXBvcnRzLmNv\nbYIJc3BsaWZlLnJ1gg10ZXJyamVuYWxzLmdhggx0aGVzaGllbGQuaW6CC3Rscmll\naGxlLm1sggt0cm95c2hhdy5tbIIQdmlzaXRzdGxvdWlzLmNvbYIPdml0YW1hc2hv\ncXRzLmdxghF3b3JkcG93ZXJlZC5jby51a4ITd29yZHByZXNzLXNlby5jby51a4IP\neWF1Z3VhcnNvb2tsLnRrgg95dWdvLWdyYWRueWEucnWCD3phdG9weWJvaHl5eS50\nazCCAQMGCisGAQQB1nkCBAIEgfQEgfEA7wB2AO5Lvbd1zmC64UJpH6vhnmajD35f\nsHLYgwDEe4l6qP3LAAABZRxF+rwAAAQDAEcwRQIgN0wv2Y7O4uoT68d6vQ3hTRp9\n2Hwim6Rx29JPIVYA9L8CIQDFXe/pJZIGzY71qts16orAUmcvatZHOnnQRf9PhhSf\ngwB1AHR+2oMxrTMQkSGcziVPQnDCv/1eQiAIxjc1eeYQe8xWAAABZRxF+wcAAAQD\nAEYwRAIgUnb/+cz4hkPOuEsXOIpofCw8LGahQ3UqRqi2vcvy8ioCIFUMsmMsoq+A\nbI0V6Rygng+bm1Psu2kc/02SrXZZFo+cMAoGCCqGSM49BAMCA0kAMEYCIQDkzCqz\no7JUNx2ivi0VJHbqAjHK/7BKEkiiE9t8L1mNdAIhAJmLU40qKa9t8Cj5/VlNFW+j\nX7Fii19CoDmLp3HGeZg9\n-----END CERTIFICATE-----\n",
            "crl_lookup_status": false,
            "hpkp_pin": "IaXoxGGXCD8qzLu92R1s2aiO/PlDP67OEEhBcdDLVKM=",
            "sha1_fingerprint": "77:EE:9D:F5:53:A6:E2:82:DA:0C:30:8F:0D:F3:B0:7D:67:AD:E1:81",
            "sha256_fingerprint": "53:ED:14:BF:25:44:50:33:F3:D7:89:F4:B6:D5:2A:E1:8A:75:B7:44:5F:4D:BD:06:16:2F:6A:C6:41:FD:DD:30"
          },
          {
            "as_dict": {
              "extensions": {
                "authority_information_access": [
                  {
                    "access_location": "http://crt.comodoca.com/COMODOECCAddTrustCA.crt",
                    "access_method": "ca_issuers"
                  },
                  {
                    "access_location": "http://ocsp.comodoca4.com",
                    "access_method": "ocsp"
                  }
                ],
                "authority_key_identifier": {
                  "authority_cert_issuer": null,
                  "authority_cert_serial_number": null,
                  "key_identifier": "75:71:a7:19:48:19:bc:9d:9d:ea:41:47:df:94:c4:48:77:99:d3:79"
                },
                "basic_constraints": {
                  "ca": true,
                  "path_len_constraint": 0
                },
                "certificate_policies": [
                  {
                    "policy_identifier": "any_policy",
                    "policy_qualifiers": null
                  },
                  {
                    "policy_identifier": "2.23.140.1.2.1",
                    "policy_qualifiers": null
                  }
                ],
                "crl_distribution_points": [
                  {
                    "crl_issuer": null,
                    "distribution_point": [
                      "http://crl.comodoca.com/COMODOECCCertificationAuthority.crl"
                    ],
                    "reasons": null
                  }
                ],
                "extended_key_usage": [
                  "server_auth",
                  "client_auth"
                ],
                "key_identifier": "40:09:61:67:f0:bc:83:71:4f:de:12:08:2c:6f:d4:d4:2b:76:3d:96",
                "key_usage": [
                  "digital_signature",
                  "key_cert_sign",
                  "crl_sign"
                ]
              },
              "issuer": {
                "common_name": "COMODO ECC Certification Authority",
                "country_name": "GB",
                "locality_name": "Salford",
                "organization_name": "COMODO CA Limited",
                "state_or_province_name": "Greater Manchester"
              },
              "public_key": {
                "algorithm": "ec",
                "curve": "secp256r1",
                "key_size": 256,
                "public_key": "04:02:38:19:81:3a:c9:69:84:70:59:02:8e:a8:8a:1f:30:df:bc:de:03:fc:79:1d:3a:25:2c:6b:41:21:18:82:ea:f9:3e:4a:e4:33:cc:12:cf:2a:43:fc:0e:f2:64:00:c0:e1:25:50:82:24:cd:b6:49:38:0f:25:47:91:48:a4:ad"
              },
              "serial_number": "121156049097932074853067657954953090221",
              "signature_algorithm": "sha384_ecdsa",
              "signature_value": "30:65:02:31:00:ac:68:47:25:80:13:4f:13:56:c0:a2:37:09:97:5a:50:c4:e7:ed:b4:61:cb:28:8a:0a:11:32:a6:e2:71:df:11:01:89:6f:07:7a:20:66:6b:18:d0:b9:2e:43:f7:52:6f:02:30:12:85:7c:8e:13:66:92:04:ba:9a:45:09:94:4a:30:61:d1:49:dc:6f:eb:e7:2d:c9:89:cf:1e:6a:7c:ec:85:ce:30:25:59:ba:81:70:34:b8:34:7f:e7:01:d1:e2:cb:52",
              "subject": {
                "common_name": "COMODO ECC Domain Validation Secure Server CA 2",
                "country_name": "GB",
                "locality_name": "Salford",
                "organization_name": "COMODO CA Limited",
                "state_or_province_name": "Greater Manchester"
              },
              "validity": {
                "not_after": "2029-09-24 23:59:59 UTC+00:00",
                "not_before": "2014-09-25 00:00:00 UTC+00:00"
              },
              "version": "v3"
            },
            "as_pem": "-----BEGIN CERTIFICATE-----\nMIIDnzCCAyWgAwIBAgIQWyXOaQfEJlVm0zkMmalUrTAKBggqhkjOPQQDAzCBhTEL\nMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UE\nBxMHU2FsZm9yZDEaMBgGA1UEChMRQ09NT0RPIENBIExpbWl0ZWQxKzApBgNVBAMT\nIkNPTU9ETyBFQ0MgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMTQwOTI1MDAw\nMDAwWhcNMjkwOTI0MjM1OTU5WjCBkjELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdy\nZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UEBxMHU2FsZm9yZDEaMBgGA1UEChMRQ09N\nT0RPIENBIExpbWl0ZWQxODA2BgNVBAMTL0NPTU9ETyBFQ0MgRG9tYWluIFZhbGlk\nYXRpb24gU2VjdXJlIFNlcnZlciBDQSAyMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcD\nQgAEAjgZgTrJaYRwWQKOqIofMN+83gP8eR06JSxrQSEYgur5PkrkM8wSzypD/A7y\nZADA4SVQgiTNtkk4DyVHkUikraOCAWYwggFiMB8GA1UdIwQYMBaAFHVxpxlIGbyd\nnepBR9+UxEh3mdN5MB0GA1UdDgQWBBRACWFn8LyDcU/eEggsb9TUK3Y9ljAOBgNV\nHQ8BAf8EBAMCAYYwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHSUEFjAUBggrBgEF\nBQcDAQYIKwYBBQUHAwIwGwYDVR0gBBQwEjAGBgRVHSAAMAgGBmeBDAECATBMBgNV\nHR8ERTBDMEGgP6A9hjtodHRwOi8vY3JsLmNvbW9kb2NhLmNvbS9DT01PRE9FQ0ND\nZXJ0aWZpY2F0aW9uQXV0aG9yaXR5LmNybDByBggrBgEFBQcBAQRmMGQwOwYIKwYB\nBQUHMAKGL2h0dHA6Ly9jcnQuY29tb2RvY2EuY29tL0NPTU9ET0VDQ0FkZFRydXN0\nQ0EuY3J0MCUGCCsGAQUFBzABhhlodHRwOi8vb2NzcC5jb21vZG9jYTQuY29tMAoG\nCCqGSM49BAMDA2gAMGUCMQCsaEclgBNPE1bAojcJl1pQxOfttGHLKIoKETKm4nHf\nEQGJbwd6IGZrGNC5LkP3Um8CMBKFfI4TZpIEuppFCZRKMGHRSdxv6+ctyYnPHmp8\n7IXOMCVZuoFwNLg0f+cB0eLLUg==\n-----END CERTIFICATE-----\n",
            "crl_lookup_status": null,
            "hpkp_pin": "x9SZw6TwIqfmvrLZ/kz1o0Ossjmn728BnBKpUFqGNVM=",
            "sha1_fingerprint": "75:CF:D9:BC:5C:EF:A1:04:EC:C1:08:2D:77:E6:33:92:CC:BA:52:91",
            "sha256_fingerprint": "CD:6C:10:8A:0E:64:1F:2C:A1:22:AA:A6:D0:3F:82:67:59:CA:E7:C6:F8:00:EA:BF:76:DC:48:B6:7C:D0:83:CE"
          },
          {
            "as_dict": {
              "extensions": {
                "basic_constraints": {
                  "ca": true,
                  "path_len_constraint": null
                },
                "key_identifier": "75:71:a7:19:48:19:bc:9d:9d:ea:41:47:df:94:c4:48:77:99:d3:79",
                "key_usage": [
                  "key_cert_sign",
                  "crl_sign"
                ]
              },
              "issuer": {
                "common_name": "COMODO ECC Certification Authority",
                "country_name": "GB",
                "locality_name": "Salford",
                "organization_name": "COMODO CA Limited",
                "state_or_province_name": "Greater Manchester"
              },
              "public_key": {
                "algorithm": "ec",
                "curve": "secp384r1",
                "key_size": 384,
                "public_key": "04:03:47:7b:2f:75:c9:82:15:85:fb:75:e4:91:16:d4:ab:62:99:f5:3e:52:0b:06:ce:41:00:7f:97:e1:0a:24:3c:1d:01:04:ee:3d:d2:8d:09:97:0c:e0:75:e4:fa:fb:77:8a:2a:f5:03:60:4b:36:8b:16:23:16:ad:09:71:f4:4a:f4:28:50:b4:fe:88:1c:6e:3f:6c:2f:2f:09:59:5b:a5:5b:0b:33:99:e2:c3:3d:89:f9:6a:2c:ef:b2:d3:06:e9"
              },
              "serial_number": "41578283867086692638256921589707938090",
              "signature_algorithm": "sha384_ecdsa",
              "signature_value": "30:65:02:31:00:ef:03:5b:7a:ac:b7:78:0a:72:b7:88:df:ff:b5:46:14:09:0a:fa:a0:e6:7d:08:c6:1a:87:bd:18:a8:73:bd:26:ca:60:0c:9d:ce:99:9f:cf:5c:0f:30:e1:be:14:31:ea:02:30:14:f4:93:3c:49:a7:33:7a:90:46:47:b3:63:7d:13:9b:4e:b7:6f:18:37:80:53:fe:dd:20:e0:35:9a:36:d1:c7:01:b9:e6:dc:dd:f3:ff:1d:2c:3a:16:57:d9:92:39:d6",
              "subject": {
                "common_name": "COMODO ECC Certification Authority",
                "country_name": "GB",
                "locality_name": "Salford",
                "organization_name": "COMODO CA Limited",
                "state_or_province_name": "Greater Manchester"
              },
              "validity": {
                "not_after": "2038-01-18 23:59:59 UTC+00:00",
                "not_before": "2008-03-06 00:00:00 UTC+00:00"
              },
              "version": "v3"
            },
            "as_pem": "-----BEGIN CERTIFICATE-----\nMIICiTCCAg+gAwIBAgIQH0evqmIAcFBUTAGem2OZKjAKBggqhkjOPQQDAzCBhTEL\nMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UE\nBxMHU2FsZm9yZDEaMBgGA1UEChMRQ09NT0RPIENBIExpbWl0ZWQxKzApBgNVBAMT\nIkNPTU9ETyBFQ0MgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMDgwMzA2MDAw\nMDAwWhcNMzgwMTE4MjM1OTU5WjCBhTELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdy\nZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UEBxMHU2FsZm9yZDEaMBgGA1UEChMRQ09N\nT0RPIENBIExpbWl0ZWQxKzApBgNVBAMTIkNPTU9ETyBFQ0MgQ2VydGlmaWNhdGlv\nbiBBdXRob3JpdHkwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAQDR3svdcmCFYX7deSR\nFtSrYpn1PlILBs5BAH+X4QokPB0BBO490o0JlwzgdeT6+3eKKvUDYEs2ixYjFq0J\ncfRK9ChQtP6IHG4/bC8vCVlbpVsLM5niwz2J+Wos77LTBumjQjBAMB0GA1UdDgQW\nBBR1cacZSBm8nZ3qQUfflMRId5nTeTAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/\nBAUwAwEB/zAKBggqhkjOPQQDAwNoADBlAjEA7wNbeqy3eApyt4jf/7VGFAkK+qDm\nfQjGGoe9GKhzvSbKYAydzpmfz1wPMOG+FDHqAjAU9JM8SaczepBGR7NjfRObTrdv\nGDeAU/7dIOA1mjbRxwG55tzd8/8dLDoWV9mSOdY=\n-----END CERTIFICATE-----\n",
            "crl_lookup_status": null,
            "hpkp_pin": "58qRu/uxh4gFezqAcERupSkRYBlBAvfcw7mEjGPLnNU=",
            "sha1_fingerprint": "9F:74:4E:9F:2B:4D:BA:EC:0F:31:2C:50:B6:56:3B:8E:2D:93:C3:11",
            "sha256_fingerprint": "17:93:92:7A:06:14:54:97:89:AD:CE:2F:8F:34:F7:F0:B6:6D:0F:3A:E3:A3:B8:4D:21:EC:15:DB:BA:4F:AD:C7"
          }
        ]
      },
      "ciphers": {
        "sslv2": {
          "accepted_cipher_list": [],
          "errored_cipher_list": [],
          "preferred_cipher": null
        },
        "sslv3": {
          "accepted_cipher_list": [],
          "errored_cipher_list": [],
          "preferred_cipher": null
        },
        "tlsv1": {
          "accepted_cipher_list": [
            {
              "dh_info": {
                "A": "0x00ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
                "B": "0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
                "Cofactor": "1",
                "Field_Type": "prime-field",
                "Generator": "0x046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
                "GeneratorType": "uncompressed",
                "GroupSize": "256",
                "Order": "0x00ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
                "Prime": "0x00ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
                "Seed": "0xc49d360886e704936a6678e1139d26b7819f7e90",
                "Type": "ECDH"
              },
              "is_anonymous": false,
              "key_size": 256,
              "openssl_name": "ECDHE-ECDSA-AES256-SHA",
              "post_handshake_response": "",
              "ssl_version": "TLSV1"
            },
            {
              "dh_info": {
                "A": "0x00ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
                "B": "0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
                "Cofactor": "1",
                "Field_Type": "prime-field",
                "Generator": "0x046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
                "GeneratorType": "uncompressed",
                "GroupSize": "256",
                "Order": "0x00ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
                "Prime": "0x00ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
                "Seed": "0xc49d360886e704936a6678e1139d26b7819f7e90",
                "Type": "ECDH"
              },
              "is_anonymous": false,
              "key_size": 128,
              "openssl_name": "ECDHE-ECDSA-AES128-SHA",
              "post_handshake_response": "",
              "ssl_version": "TLSV1"
            }
          ],
          "errored_cipher_list": [],
          "preferred_cipher": {
            "dh_info": {
              "A": "0x00ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
              "B": "0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
              "Cofactor": "1",
              "Field_Type": "prime-field",
              "Generator": "0x046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
              "GeneratorType": "uncompressed",
              "GroupSize": "256",
              "Order": "0x00ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
              "Prime": "0x00ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
              "Seed": "0xc49d360886e704936a6678e1139d26b7819f7e90",
              "Type": "ECDH"
            },
            "is_anonymous": false,
            "key_size": 128,
            "openssl_name": "ECDHE-ECDSA-AES128-SHA",
            "post_handshake_response": "",
            "ssl_version": "TLSV1"
          }
        },
        "tlsv1_1": {
          "accepted_cipher_list": [
            {
              "dh_info": {
                "A": "0x00ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
                "B": "0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
                "Cofactor": "1",
                "Field_Type": "prime-field",
                "Generator": "0x046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
                "GeneratorType": "uncompressed",
                "GroupSize": "256",
                "Order": "0x00ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
                "Prime": "0x00ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
                "Seed": "0xc49d360886e704936a6678e1139d26b7819f7e90",
                "Type": "ECDH"
              },
              "is_anonymous": false,
              "key_size": 256,
              "openssl_name": "ECDHE-ECDSA-AES256-SHA",
              "post_handshake_response": "",
              "ssl_version": "TLSV1_1"
            },
            {
              "dh_info": {
                "A": "0x00ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
                "B": "0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
                "Cofactor": "1",
                "Field_Type": "prime-field",
                "Generator": "0x046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
                "GeneratorType": "uncompressed",
                "GroupSize": "256",
                "Order": "0x00ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
                "Prime": "0x00ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
                "Seed": "0xc49d360886e704936a6678e1139d26b7819f7e90",
                "Type": "ECDH"
              },
              "is_anonymous": false,
              "key_size": 128,
              "openssl_name": "ECDHE-ECDSA-AES128-SHA",
              "post_handshake_response": "",
              "ssl_version": "TLSV1_1"
            }
          ],
          "errored_cipher_list": [],
          "preferred_cipher": {
            "dh_info": {
              "A": "0x00ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
              "B": "0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
              "Cofactor": "1",
              "Field_Type": "prime-field",
              "Generator": "0x046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
              "GeneratorType": "uncompressed",
              "GroupSize": "256",
              "Order": "0x00ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
              "Prime": "0x00ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
              "Seed": "0xc49d360886e704936a6678e1139d26b7819f7e90",
              "Type": "ECDH"
            },
            "is_anonymous": false,
            "key_size": 128,
            "openssl_name": "ECDHE-ECDSA-AES128-SHA",
            "post_handshake_response": "",
            "ssl_version": "TLSV1_1"
          }
        },
        "tlsv1_2": {
          "accepted_cipher_list": [
            {
              "dh_info": {
                "A": "0x00ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
                "B": "0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
                "Cofactor": "1",
                "Field_Type": "prime-field",
                "Generator": "0x046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
                "GeneratorType": "uncompressed",
                "GroupSize": "256",
                "Order": "0x00ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
                "Prime": "0x00ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
                "Seed": "0xc49d360886e704936a6678e1139d26b7819f7e90",
                "Type": "ECDH"
              },
              "is_anonymous": false,
              "key_size": 256,
              "openssl_name": "ECDHE-ECDSA-AES256-SHA",
              "post_handshake_response": "",
              "ssl_version": "TLSV1_2"
            },
            {
              "dh_info": {
                "A": "0x00ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
                "B": "0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
                "Cofactor": "1",
                "Field_Type": "prime-field",
                "Generator": "0x046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
                "GeneratorType": "uncompressed",
                "GroupSize": "256",
                "Order": "0x00ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
                "Prime": "0x00ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
                "Seed": "0xc49d360886e704936a6678e1139d26b7819f7e90",
                "Type": "ECDH"
              },
              "is_anonymous": false,
              "key_size": 256,
              "openssl_name": "ECDHE-ECDSA-AES256-SHA384",
              "post_handshake_response": "",
              "ssl_version": "TLSV1_2"
            },
            {
              "dh_info": null,
              "is_anonymous": false,
              "key_size": 256,
              "openssl_name": "ECDHE-ECDSA-CHACHA20-POLY1305",
              "post_handshake_response": "",
              "ssl_version": "TLSV1_2"
            },
            {
              "dh_info": {
                "A": "0x00ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
                "B": "0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
                "Cofactor": "1",
                "Field_Type": "prime-field",
                "Generator": "0x046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
                "GeneratorType": "uncompressed",
                "GroupSize": "256",
                "Order": "0x00ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
                "Prime": "0x00ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
                "Seed": "0xc49d360886e704936a6678e1139d26b7819f7e90",
                "Type": "ECDH"
              },
              "is_anonymous": false,
              "key_size": 256,
              "openssl_name": "ECDHE-ECDSA-AES256-GCM-SHA384",
              "post_handshake_response": "",
              "ssl_version": "TLSV1_2"
            },
            {
              "dh_info": {
                "A": "0x00ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
                "B": "0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
                "Cofactor": "1",
                "Field_Type": "prime-field",
                "Generator": "0x046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
                "GeneratorType": "uncompressed",
                "GroupSize": "256",
                "Order": "0x00ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
                "Prime": "0x00ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
                "Seed": "0xc49d360886e704936a6678e1139d26b7819f7e90",
                "Type": "ECDH"
              },
              "is_anonymous": false,
              "key_size": 128,
              "openssl_name": "ECDHE-ECDSA-AES128-SHA256",
              "post_handshake_response": "",
              "ssl_version": "TLSV1_2"
            },
            {
              "dh_info": {
                "A": "0x00ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
                "B": "0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
                "Cofactor": "1",
                "Field_Type": "prime-field",
                "Generator": "0x046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
                "GeneratorType": "uncompressed",
                "GroupSize": "256",
                "Order": "0x00ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
                "Prime": "0x00ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
                "Seed": "0xc49d360886e704936a6678e1139d26b7819f7e90",
                "Type": "ECDH"
              },
              "is_anonymous": false,
              "key_size": 128,
              "openssl_name": "ECDHE-ECDSA-AES128-GCM-SHA256",
              "post_handshake_response": "",
              "ssl_version": "TLSV1_2"
            },
            {
              "dh_info": {
                "A": "0x00ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
                "B": "0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
                "Cofactor": "1",
                "Field_Type": "prime-field",
                "Generator": "0x046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
                "GeneratorType": "uncompressed",
                "GroupSize": "256",
                "Order": "0x00ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
                "Prime": "0x00ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
                "Seed": "0xc49d360886e704936a6678e1139d26b7819f7e90",
                "Type": "ECDH"
              },
              "is_anonymous": false,
              "key_size": 128,
              "openssl_name": "ECDHE-ECDSA-AES128-SHA",
              "post_handshake_response": "",
              "ssl_version": "TLSV1_2"
            }
          ],
          "errored_cipher_list": [],
          "preferred_cipher": {
            "dh_info": {
              "A": "0x00ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
              "B": "0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
              "Cofactor": "1",
              "Field_Type": "prime-field",
              "Generator": "0x046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
              "GeneratorType": "uncompressed",
              "GroupSize": "256",
              "Order": "0x00ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
              "Prime": "0x00ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
              "Seed": "0xc49d360886e704936a6678e1139d26b7819f7e90",
              "Type": "ECDH"
            },
            "is_anonymous": false,
            "key_size": 128,
            "openssl_name": "ECDHE-ECDSA-AES128-GCM-SHA256",
            "post_handshake_response": "",
            "ssl_version": "TLSV1_2"
          }
        },
        "tlsv1_3": {
          "accepted_cipher_list": [
            {
              "dh_info": null,
              "is_anonymous": false,
              "key_size": 256,
              "openssl_name": "TLS13-AES-256-GCM-SHA384",
              "post_handshake_response": "",
              "ssl_version": "TLSV1_3"
            },
            {
              "dh_info": null,
              "is_anonymous": false,
              "key_size": 256,
              "openssl_name": "TLS13-CHACHA20-POLY1305-SHA256",
              "post_handshake_response": "",
              "ssl_version": "TLSV1_3"
            },
            {
              "dh_info": null,
              "is_anonymous": false,
              "key_size": 128,
              "openssl_name": "TLS13-AES-128-GCM-SHA256",
              "post_handshake_response": "",
              "ssl_version": "TLSV1_3"
            }
          ],
          "errored_cipher_list": [],
          "preferred_cipher": null
        }
      },
      "server_info": {
        "client_auth_credentials": null,
        "client_auth_requirement": "DISABLED",
        "highest_ssl_version_supported": "TLSV1_2",
        "hostname": "binaryedge.io",
        "http_tunneling_settings": null,
        "ip_address": "104.28.7.147",
        "openssl_cipher_string_supported": "ECDHE-ECDSA-CHACHA20-POLY1305",
        "port": 443,
        "tls_server_name_indication": "binaryedge.io",
        "tls_wrapped_protocol": "PLAIN_TLS",
        "xmpp_to_hostname": null
      },
      "vulnerabilities": {
        "compression": {
          "compression_name": null,
          "supports_compression": true
        },
        "fallback": {
          "supports_fallback_scsv": true
        },
        "heartbleed": {
          "is_vulnerable_to_heartbleed": false
        },
        "openssl_ccs": {
          "is_vulnerable_to_ccs_injection": false
        },
        "renegotiation": {
          "accepts_client_renegotiation": false,
          "supports_secure_renegotiation": true
        },
        "robot": {
          "robot_result_enum": "NOT_VULNERABLE_RSA_NOT_SUPPORTED"
        }
      }
    },
    ...
  }
}
```
