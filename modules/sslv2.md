# SSLv2

SSL Module can analyze the SSL configuration of a server by connecting to it.
It is designed to be fast and comprehensive and should help organizations and testers identify misconfigurations affecting their SSL servers.

By default, the SSL module runs in full mode, where it will run all tests including the cipher suite tests which are very noisy. It is possible to disable the cipher tests by selecting the fast mode, i.e., changing the configuration key **ssl_mode** to **fast**.

You can also run only specific cypher suites at a time, by changing **cypher_mode** to one of **sslv2**, **sslv3**, **tlsv1**, **tlsv1_1**, **tlsv1_2**, **tlsv1_3**. 


## SSL Request Example

```
curl -v -L https://api.binaryedge.io/v1/tasks -d '{"type":"scan", "options":[{"targets":["X.X.X.X"], "ports":[{"port":443, "protocol":"tcp", "modules":["sslv2"], "config":{}}]}]}' -H "X-Token:<Token>"
```

### SSL Request Options

These are optional parameters that can alter the behaviour of the module. These options can be inserted into the "config" object on the request.

  * sni - Set HTTPS Server Name Indication
    * "config":{"sni":"google.com"}
  * ssl_mode - Disable the cipher tests
    * "config":{"ssl_mode":"fast"}
  * cypher_mode - Run only specific cipher tests
    * "config":{"cypher_mode":"tls1_3"}
  * robot - Run only ROBOT vuln detection
    * "config":{"robot":"1"}

## Schema

### SSL Event Schema

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
              "serialNumber": "string",
              "subject": {
                "commonName": "string",
                "localityName": "string",
                "organizationName": "string",
                "organizationalUnitName": "string",
                "countryName": "string",
                "stateOrProvinceName": "string"
              },
              "subjectPublicKeyInfo": {
                "publicKeyAlgorithm": "string",
                "publicKeySize": "string",
                "publicKey": {
                  "modulus": "string",
                  "exponent": "string",
                  "curve": "string",
                  "pub": "string"
                }
              },
              "validity": {
                "notAfter": "string",
                "notBefore": "string"
              },
              "version": "int",
              "issuer": {
                "commonName": "string",
                "localityName": "string",
                "organizationalUnitName": "string",
                "organizationName": "string",
                "countryName": "string",
                "stateOrProvinceName": "string"
              },
              "signatureAlgorithm": "string",
              "signatureValue": "string"
            },
            "sha1_fingerprint": "string",
            "hpkp_pin": "string",
            "as_pem": "string"
          },
          ...
        ],
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

*Variables description from https://nabla-c0d3.github.io/sslyze/documentation/available-scan-commands.html, https://github.com/nabla-c0d3/sslyze/blob/1.4.3/sslyze/server_connectivity_info.py and https://godoc.org/github.com/lair-framework/go-sslyze*

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
      * serialNumber - the certificate serial number
      * subject - subject contains the target's certificate subject information
        * commonName - common name of the subject
        * localityName - locality of the subject
        * organizationName - organization name of the subject
        * organizationalUnitName - organizational unit name of the subject
        * countryName - country of the subject
        * stateOrProvinceName - state or province of the subject
      * subjectPublicKeyInfo - contains information about the public key stored in the certificate
        * publicKeyAlgorithm - algorithm used to create the public key
        * publicKeySize - size of the public key
        * publicKey - contains the target public key
          * modulus - returns the value of attribute modulus
          * exponent - returns the value of attribute exponent
        * validity -  contains the target's certificate validity
          * notAfter - expiration date of the certificate
          * notBefore - date from which the certificate is valid
      * version - the certificate SSL version
      * issuer - contains the target's certificate issuer information
        * commonName - common name of the issuer
        * localityName - locality of the issuer
        * organizationName - organization name of the issuer
        * organiationalUnitName - organizational name of the issuer
        * countryName - country of the issuer
        * stateOrProvinceName - stae or province of the issuer
      * signatureAlgorithm - the certificate signature algorithm
      * signatureValue - the certificate signature
    * sha1_fingerprint - the SHA1 fingerprint of the certificate
    * hpkp_pin - HTTP Public Key pin
    * as_pem - the certificate in PEM format
  * verified_certificate_chain - verified certificate chain, all the fields are the same as certificate_chain
  * successful_trust_store - the trust store successfully used for validation
    * name - the human-readable name of the trust store
    * version - the human-readable version or date of the trust store
  * path_validation_result_list - the list of attempts at validating the server's certificate chain path using the trust stores packaged (Mozilla, Apple, etc.)
    * is_certificate_trusted - whether the certificate chain is trusted when using supplied the trust_store
    * trust_store - the trust store used for validation
      * name - the human-readable name of the trust store
      * version - the human-readable version or date of the trust store
    * verify_string - the string returned by OpenSSL's validation function
* server_info - the server against which the command was run
  * ssl_cipher_supported - one of the ssl ciphers supported by the server
  * hostname - the server's hostname
  * client_auth_requirement(_string) - does the server require the client to be authenticated
  * highest_ssl_version_supported(_string) - the highest version of ssl supported for connections
  * port - the server's TLS port number. If not supplied, the default port number for the specified `tls_wrapped_protocol` will be used
  * http_tunneling_settings - settings defined for http tunnel
  * ip_address - the server's IP address. If not supplied, a DNS lookup for the specified `hostname` will be performed. If `http_tunneling_settings` is specified, `ip_address` cannot be supplied as the HTTP proxy will be responsible for looking up and connecting to the server to be scanned.
  * client_auth_credentials - The client certificate and private key needed to perform mutual authentication with the server. If not supplied, will attempt to connect to the server without performing mutual authentication
  * tls_wrapped_protocol(_string) - the protocol wrapped in TLS that the server expects. It allows to figure out how to establish a (Start)TLS connection to the server and what kind of "hello" message (SMTP, XMPP, etc.) to send to the server after the handshake was completed. If not supplied, standard TLS will be used.
  * xmpp_to_hostname - the hostname to set within the `to` attribute of the XMPP stream. If not supplied, the specified `hostname` will be used. Should only be set if the supplied `tls_wrapped_protocol` is an XMPP protocol
  * tls_server_name_indication - the hostname to set within the Server Name Indication TLS extension. If not supplied, the specified `hostname` will be used

## SSL Event Example

### Request

```
curl https://api.binaryedge.io/v1/tasks -d '{"type":"scan", "description": "SSL Request", "options":[{"targets":["X.X.X.X"], "ports":[{"port":"443", "protocol":"tcp", "modules": ["sslv2"], "config":{"sni":"www.binaryedge.io", "ssl_mode":"full"}}]}]}' -H "X-Token:<Token>"
```

### Response

```json
{
  "result": {
    "data": {
      "vulnerabilities": {
        "renegotiation": {
          "supports_secure_renegotiation": true,
          "accepts_client_renegotiation": false
        },
        "openssl_ccs": {
          "is_vulnerable_to_ccs_injection": false
        },
        "heartbleed": {
          "is_vulnerable_to_heartbleed": false
        },
        "fallback": {
          "supports_fallback_scsv": true
        },
        "compression": {
          "supports_compression": true,
          "compression_name": null
        }
      },
      "server_info": {
        "xmpp_to_hostname": null,
        "tls_wrapped_protocol": "PLAIN_TLS",
        "tls_server_name_indication": "binaryedge.io",
        "client_auth_credentials": null,
        "client_auth_requirement": "DISABLED",
        "highest_ssl_version_supported": "TLSV1_2",
        "hostname": "binaryedge.io",
        "http_tunneling_settings": null,
        "ip_address": "104.28.6.147",
        "openssl_cipher_string_supported": "ECDHE-ECDSA-CHACHA20-POLY1305",
        "port": 443
      },
      "ciphers": {
        "tlsv1_3": {
          "preferred_cipher": null,
          "errored_cipher_list": [],
          "accepted_cipher_list": [
            {
              "ssl_version": "TLSV1_3",
              "post_handshake_response": "",
              "openssl_name": "TLS13-CHACHA20-POLY1305-SHA256",
              "key_size": 256,
              "is_anonymous": false,
              "dh_info": null
            },
            {
              "ssl_version": "TLSV1_3",
              "post_handshake_response": "",
              "openssl_name": "TLS13-AES-256-GCM-SHA384",
              "key_size": 256,
              "is_anonymous": false,
              "dh_info": null
            },
            {
              "ssl_version": "TLSV1_3",
              "post_handshake_response": "",
              "openssl_name": "TLS13-AES-128-GCM-SHA256",
              "key_size": 128,
              "is_anonymous": false,
              "dh_info": null
            }
          ]
        },
        "tlsv1_2": {
          "preferred_cipher": {
            "ssl_version": "TLSV1_2",
            "post_handshake_response": "",
            "openssl_name": "ECDHE-ECDSA-AES128-GCM-SHA256",
            "key_size": 128,
            "is_anonymous": false,
            "dh_info": {
              "Type": "ECDH",
              "Seed": "0xc49d360886e704936a6678e1139d26b7819f7e90",
              "Prime": "0x00ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
              "A": "0x00ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
              "B": "0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
              "Cofactor": "1",
              "Field_Type": "prime-field",
              "Generator": "0x046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
              "GeneratorType": "uncompressed",
              "GroupSize": "256",
              "Order": "0x00ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
            }
          },
          "errored_cipher_list": [],
          "accepted_cipher_list": [
            {
              "ssl_version": "TLSV1_2",
              "post_handshake_response": "",
              "openssl_name": "ECDHE-ECDSA-AES256-SHA",
              "key_size": 256,
              "is_anonymous": false,
              "dh_info": {
                "Type": "ECDH",
                "Seed": "0xc49d360886e704936a6678e1139d26b7819f7e90",
                "Prime": "0x00ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
                "A": "0x00ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
                "B": "0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
                "Cofactor": "1",
                "Field_Type": "prime-field",
                "Generator": "0x046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
                "GeneratorType": "uncompressed",
                "GroupSize": "256",
                "Order": "0x00ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
              }
            },
            {
              "ssl_version": "TLSV1_2",
              "post_handshake_response": "",
              "openssl_name": "ECDHE-ECDSA-AES256-GCM-SHA384",
              "key_size": 256,
              "is_anonymous": false,
              "dh_info": {
                "Type": "ECDH",
                "Seed": "0xc49d360886e704936a6678e1139d26b7819f7e90",
                "Prime": "0x00ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
                "A": "0x00ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
                "B": "0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
                "Cofactor": "1",
                "Field_Type": "prime-field",
                "Generator": "0x046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
                "GeneratorType": "uncompressed",
                "GroupSize": "256",
                "Order": "0x00ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
              }
            },
            {
              "ssl_version": "TLSV1_2",
              "post_handshake_response": "",
              "openssl_name": "ECDHE-ECDSA-AES256-SHA384",
              "key_size": 256,
              "is_anonymous": false,
              "dh_info": {
                "Type": "ECDH",
                "Seed": "0xc49d360886e704936a6678e1139d26b7819f7e90",
                "Prime": "0x00ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
                "A": "0x00ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
                "B": "0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
                "Cofactor": "1",
                "Field_Type": "prime-field",
                "Generator": "0x046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
                "GeneratorType": "uncompressed",
                "GroupSize": "256",
                "Order": "0x00ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
              }
            },
            {
              "ssl_version": "TLSV1_2",
              "post_handshake_response": "",
              "openssl_name": "ECDHE-ECDSA-CHACHA20-POLY1305",
              "key_size": 256,
              "is_anonymous": false,
              "dh_info": null
            },
            {
              "ssl_version": "TLSV1_2",
              "post_handshake_response": "",
              "openssl_name": "ECDHE-ECDSA-AES128-SHA256",
              "key_size": 128,
              "is_anonymous": false,
              "dh_info": {
                "Type": "ECDH",
                "Seed": "0xc49d360886e704936a6678e1139d26b7819f7e90",
                "Prime": "0x00ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
                "A": "0x00ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
                "B": "0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
                "Cofactor": "1",
                "Field_Type": "prime-field",
                "Generator": "0x046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
                "GeneratorType": "uncompressed",
                "GroupSize": "256",
                "Order": "0x00ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
              }
            },
            {
              "ssl_version": "TLSV1_2",
              "post_handshake_response": "",
              "openssl_name": "ECDHE-ECDSA-AES128-GCM-SHA256",
              "key_size": 128,
              "is_anonymous": false,
              "dh_info": {
                "Type": "ECDH",
                "Seed": "0xc49d360886e704936a6678e1139d26b7819f7e90",
                "Prime": "0x00ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
                "A": "0x00ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
                "B": "0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
                "Cofactor": "1",
                "Field_Type": "prime-field",
                "Generator": "0x046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
                "GeneratorType": "uncompressed",
                "GroupSize": "256",
                "Order": "0x00ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
              }
            },
            {
              "ssl_version": "TLSV1_2",
              "post_handshake_response": "",
              "openssl_name": "ECDHE-ECDSA-AES128-SHA",
              "key_size": 128,
              "is_anonymous": false,
              "dh_info": {
                "Type": "ECDH",
                "Seed": "0xc49d360886e704936a6678e1139d26b7819f7e90",
                "Prime": "0x00ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
                "A": "0x00ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
                "B": "0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
                "Cofactor": "1",
                "Field_Type": "prime-field",
                "Generator": "0x046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
                "GeneratorType": "uncompressed",
                "GroupSize": "256",
                "Order": "0x00ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
              }
            }
          ]
        },
        "tlsv1_1": {
          "preferred_cipher": {
            "ssl_version": "TLSV1_1",
            "post_handshake_response": "",
            "openssl_name": "ECDHE-ECDSA-AES128-SHA",
            "key_size": 128,
            "is_anonymous": false,
            "dh_info": {
              "Type": "ECDH",
              "Seed": "0xc49d360886e704936a6678e1139d26b7819f7e90",
              "Prime": "0x00ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
              "A": "0x00ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
              "B": "0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
              "Cofactor": "1",
              "Field_Type": "prime-field",
              "Generator": "0x046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
              "GeneratorType": "uncompressed",
              "GroupSize": "256",
              "Order": "0x00ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
            }
          },
          "errored_cipher_list": [],
          "accepted_cipher_list": [
            {
              "ssl_version": "TLSV1_1",
              "post_handshake_response": "",
              "openssl_name": "ECDHE-ECDSA-AES256-SHA",
              "key_size": 256,
              "is_anonymous": false,
              "dh_info": {
                "Type": "ECDH",
                "Seed": "0xc49d360886e704936a6678e1139d26b7819f7e90",
                "Prime": "0x00ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
                "A": "0x00ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
                "B": "0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
                "Cofactor": "1",
                "Field_Type": "prime-field",
                "Generator": "0x046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
                "GeneratorType": "uncompressed",
                "GroupSize": "256",
                "Order": "0x00ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
              }
            },
            {
              "ssl_version": "TLSV1_1",
              "post_handshake_response": "",
              "openssl_name": "ECDHE-ECDSA-AES128-SHA",
              "key_size": 128,
              "is_anonymous": false,
              "dh_info": {
                "Type": "ECDH",
                "Seed": "0xc49d360886e704936a6678e1139d26b7819f7e90",
                "Prime": "0x00ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
                "A": "0x00ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
                "B": "0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
                "Cofactor": "1",
                "Field_Type": "prime-field",
                "Generator": "0x046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
                "GeneratorType": "uncompressed",
                "GroupSize": "256",
                "Order": "0x00ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
              }
            }
          ]
        },
        "tlsv1": {
          "preferred_cipher": {
            "ssl_version": "TLSV1",
            "post_handshake_response": "",
            "openssl_name": "ECDHE-ECDSA-AES128-SHA",
            "key_size": 128,
            "is_anonymous": false,
            "dh_info": {
              "Type": "ECDH",
              "Seed": "0xc49d360886e704936a6678e1139d26b7819f7e90",
              "Prime": "0x00ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
              "A": "0x00ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
              "B": "0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
              "Cofactor": "1",
              "Field_Type": "prime-field",
              "Generator": "0x046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
              "GeneratorType": "uncompressed",
              "GroupSize": "256",
              "Order": "0x00ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
            }
          },
          "errored_cipher_list": [],
          "accepted_cipher_list": [
            {
              "ssl_version": "TLSV1",
              "post_handshake_response": "",
              "openssl_name": "ECDHE-ECDSA-AES256-SHA",
              "key_size": 256,
              "is_anonymous": false,
              "dh_info": {
                "Type": "ECDH",
                "Seed": "0xc49d360886e704936a6678e1139d26b7819f7e90",
                "Prime": "0x00ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
                "A": "0x00ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
                "B": "0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
                "Cofactor": "1",
                "Field_Type": "prime-field",
                "Generator": "0x046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
                "GeneratorType": "uncompressed",
                "GroupSize": "256",
                "Order": "0x00ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
              }
            },
            {
              "ssl_version": "TLSV1",
              "post_handshake_response": "",
              "openssl_name": "ECDHE-ECDSA-AES128-SHA",
              "key_size": 128,
              "is_anonymous": false,
              "dh_info": {
                "Type": "ECDH",
                "Seed": "0xc49d360886e704936a6678e1139d26b7819f7e90",
                "Prime": "0x00ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
                "A": "0x00ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
                "B": "0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
                "Cofactor": "1",
                "Field_Type": "prime-field",
                "Generator": "0x046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
                "GeneratorType": "uncompressed",
                "GroupSize": "256",
                "Order": "0x00ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
              }
            }
          ]
        },
        "sslv3": {
          "preferred_cipher": null,
          "errored_cipher_list": [],
          "accepted_cipher_list": []
        },
        "sslv2": {
          "preferred_cipher": null,
          "errored_cipher_list": [],
          "accepted_cipher_list": []
        }
      },
      "cert_info": {
        "verified_certificate_chain": [
          {
            "sha1_fingerprint": "89aea13db4e38f4095a1ffd6debb27114d27f33a",
            "hpkp_pin": "IaXoxGGXCD8qzLu92R1s2aiO/PlDP67OEEhBcdDLVKM=",
            "as_pem": "-----BEGIN CERTIFICATE-----\nMIIKpjCCCkygAwIBAgIQG8/FK/y/zZpGIhUD4xRrhTAKBggqhkjOPQQDAjCBkjEL\nMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UE\nBxMHU2FsZm9yZDEaMBgGA1UEChMRQ09NT0RPIENBIExpbWl0ZWQxODA2BgNVBAMT\nL0NPTU9ETyBFQ0MgRG9tYWluIFZhbGlkYXRpb24gU2VjdXJlIFNlcnZlciBDQSAy\nMB4XDTE4MDgwMjAwMDAwMFoXDTE5MDIwODIzNTk1OVowbDEhMB8GA1UECxMYRG9t\nYWluIENvbnRyb2wgVmFsaWRhdGVkMSEwHwYDVQQLExhQb3NpdGl2ZVNTTCBNdWx0\naS1Eb21haW4xJDAiBgNVBAMTG3NuaTE3NzUyOC5jbG91ZGZsYXJlc3NsLmNvbTBZ\nMBMGByqGSM49AgEGCCqGSM49AwEHA0IABOWOa3A0++wfMHhWZATKN/99EvxV5ZPz\nyYVMDuRAI+RvIMCle6mdkuql12OuE3S8V4hgAdKWbBUwM7O4rq/4F++jgginMIII\nozAfBgNVHSMEGDAWgBRACWFn8LyDcU/eEggsb9TUK3Y9ljAdBgNVHQ4EFgQUKPuH\nno33C/KtLHm3+Dh1EwveCvAwDgYDVR0PAQH/BAQDAgeAMAwGA1UdEwEB/wQCMAAw\nHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCME8GA1UdIARIMEYwOgYLKwYB\nBAGyMQECAgcwKzApBggrBgEFBQcCARYdaHR0cHM6Ly9zZWN1cmUuY29tb2RvLmNv\nbS9DUFMwCAYGZ4EMAQIBMFYGA1UdHwRPME0wS6BJoEeGRWh0dHA6Ly9jcmwuY29t\nb2RvY2E0LmNvbS9DT01PRE9FQ0NEb21haW5WYWxpZGF0aW9uU2VjdXJlU2VydmVy\nQ0EyLmNybDCBiAYIKwYBBQUHAQEEfDB6MFEGCCsGAQUFBzAChkVodHRwOi8vY3J0\nLmNvbW9kb2NhNC5jb20vQ09NT0RPRUNDRG9tYWluVmFsaWRhdGlvblNlY3VyZVNl\ncnZlckNBMi5jcnQwJQYIKwYBBQUHMAGGGWh0dHA6Ly9vY3NwLmNvbW9kb2NhNC5j\nb20wggXmBgNVHREEggXdMIIF2YIbc25pMTc3NTI4LmNsb3VkZmxhcmVzc2wuY29t\nggkqLjQwZnkuaW+CFSouN3N0YXJob3RlbHMuc2NpZW5jZYIJKi5hdGxzLnRvgg8q\nLmJpbmFyeWVkZ2UuaW+CDCouYm9leXJ0bi5jZoISKi5jYXZpbmd0b3VyLnRyYWRl\ngg8qLmNvZGVhdmVudWUubGuCECouY29udGVudC5zY2hvb2yCDyouY29yc2VjdHJh\nLmNvbYIWKi5jb3p5c2xlZXBvdXRkb29yLmNvbYIRKi5kZXl2YXN0YXRvcnMuZ3GC\nDCouZG1kdmVyaS5ydYINKi5nZXR2ZW5rLmNvbYIMKi5naXp6MTQzLnRrghsqLmd5\nYW5nYW5nYWNoaGluZHdhcmEuY28uaW6CFSouaGFwaGF6YXJkZ291cm1ldC5tbIIR\nKi5ob21lcm9vbS5zY2hvb2yCFCouaG9va2Vkb25jb3VudHJ5Lm1sghoqLmlpc21l\ndWNjaS5hbHRlcnZpc3RhLm9yZ4IJKi5penNlLmNmgg8qLmpveXpvbmUuY28uemGC\nDioubGluZGVob2VrLm5sghAqLmxvYWdxbnJhbmNoLm1sggsqLm1vZmEuYXNpYYIM\nKi5ub3dhbnMuY29tgiAqLnBpenplcmlhLWFsZnJlZG8tb2JlcmhhdXNlbi5kZYIU\nKi5wb3J0Y2l0eXNwb3J0cy5uZXSCEioucHVibGlzaGVyLnNjaG9vbIIUKi5zZXJp\nZWFtb25hbW91ci5jb22CECouc3AtaW1wb3J0cy5jb22CCyouc3BsaWZlLnJ1gg8q\nLnRlcnJqZW5hbHMuZ2GCDioudGhlc2hpZWxkLmlugg0qLnRscmllaGxlLm1sgg0q\nLnRyb3lzaGF3Lm1sghIqLnZpc2l0c3Rsb3Vpcy5jb22CESoudml0YW1hc2hvcXRz\nLmdxghMqLndvcmRwb3dlcmVkLmNvLnVrghUqLndvcmRwcmVzcy1zZW8uY28udWuC\nESoueWF1Z3VhcnNvb2tsLnRrghEqLnl1Z28tZ3JhZG55YS5ydYIRKi56YXRvcHli\nb2h5eXkudGuCBzQwZnkuaW+CEzdzdGFyaG90ZWxzLnNjaWVuY2WCB2F0bHMudG+C\nDWJpbmFyeWVkZ2UuaW+CCmJvZXlydG4uY2aCEGNhdmluZ3RvdXIudHJhZGWCDWNv\nZGVhdmVudWUubGuCDmNvbnRlbnQuc2Nob29sgg1jb3JzZWN0cmEuY29tghRjb3p5\nc2xlZXBvdXRkb29yLmNvbYIPZGV5dmFzdGF0b3JzLmdxggpkbWR2ZXJpLnJ1ggtn\nZXR2ZW5rLmNvbYIKZ2l6ejE0My50a4IZZ3lhbmdhbmdhY2hoaW5kd2FyYS5jby5p\nboITaGFwaGF6YXJkZ291cm1ldC5tbIIPaG9tZXJvb20uc2Nob29sghJob29rZWRv\nbmNvdW50cnkubWyCGGlpc21ldWNjaS5hbHRlcnZpc3RhLm9yZ4IHaXpzZS5jZoIN\nam95em9uZS5jby56YYIMbGluZGVob2VrLm5sgg5sb2FncW5yYW5jaC5tbIIJbW9m\nYS5hc2lhggpub3dhbnMuY29tgh5waXp6ZXJpYS1hbGZyZWRvLW9iZXJoYXVzZW4u\nZGWCEnBvcnRjaXR5c3BvcnRzLm5ldIIQcHVibGlzaGVyLnNjaG9vbIISc2VyaWVh\nbW9uYW1vdXIuY29tgg5zcC1pbXBvcnRzLmNvbYIJc3BsaWZlLnJ1gg10ZXJyamVu\nYWxzLmdhggx0aGVzaGllbGQuaW6CC3RscmllaGxlLm1sggt0cm95c2hhdy5tbIIQ\ndmlzaXRzdGxvdWlzLmNvbYIPdml0YW1hc2hvcXRzLmdxghF3b3JkcG93ZXJlZC5j\nby51a4ITd29yZHByZXNzLXNlby5jby51a4IPeWF1Z3VhcnNvb2tsLnRrgg95dWdv\nLWdyYWRueWEucnWCD3phdG9weWJvaHl5eS50azCCAQQGCisGAQQB1nkCBAIEgfUE\ngfIA8AB3AO5Lvbd1zmC64UJpH6vhnmajD35fsHLYgwDEe4l6qP3LAAABZPh1Db4A\nAAQDAEgwRgIhAKkcUrf+YIQRH4IyWEcM+89Qkhua5KzoxlPrw8xoGg7sAiEAkSDH\nNpZ0GXnbkBlZmg3xKHXHv7ttjG/f7Cl9WK7I5qkAdQB0ftqDMa0zEJEhnM4lT0Jw\nwr/9XkIgCMY3NXnmEHvMVgAAAWT4dQ4ZAAAEAwBGMEQCIAiaiLfYhO3YTHYg6HeR\nk4cdCu7ioXjSDNEjJefJ6INCAiASFSKYBogLGnC6TfmeFmNSw984vxyonew00uxQ\nbeLIdDAKBggqhkjOPQQDAgNIADBFAiBw8N1AtSrs5yQy3cR4ZEtMAfyf5+P2RM5+\neuMIGQ91SQIhAOIex5AxbqqIPIcze1vZsn22J6DvW5VwqSeXN2rWoEdV\n-----END CERTIFICATE-----\n",
            "as_dict": {
              "version": 2,
              "extensions": {
                "X509v3 Certificate Policies": {
                  "Policy": [
                    "1.3.6.1.4.1.6449.1.2.2.7",
                    "2.23.140.1.2.1"
                  ],
                  "CPS": [
                    "https://secure.comodo.com/CPS"
                  ]
                },
                "X509v3 CRL Distribution Points": {
                  "UniformResourceIdentifier": [],
                  "Full Name": [
                    ""
                  ]
                },
                "X509v3 Basic Constraints": {
                  "CA": [
                    "FALSE"
                  ]
                },
                "X509v3 Authority Key Identifier": "keyid:40:09:61:67:f0:bc:83:71:4f:de:12:08:2c:6f:d4:d4:2b:76:3d:96",
                "Authority Information Access": {
                  "caIssuers": {
                    "UniformResourceIdentifier": [
                      "http://crt.comodoca4.com/COMODOECCDomainValidationSecureServerCA2.crt"
                    ]
                  },
                  "OCSP": {
                    "UniformResourceIdentifier": [
                      "http://ocsp.comodoca4.com"
                    ]
                  }
                }
              },
              "issuer": {
                "stateOrProvinceName": "Greater Manchester",
                "organizationName": "COMODO CA Limited",
                "localityName": "Salford",
                "countryName": "GB",
                "commonName": "COMODO ECC Domain Validation Secure Server CA 2"
              },
              "serialNumber": "1BCFC52BFCBFCD9A46221503E3146B85",
              "signatureAlgorithm": "ecdsa-with-SHA256",
              "signatureValue": "30:45:02:20:70:f0:dd:40:b5:2a:ec:e7:24:32:dd:c4:78:64:4b:4c:01:fc:9f:e7:e3:f6:44:ce:7e:7a:e3:08:19:0f:75:49:02:21:00:e2:1e:c7:90:31:6e:aa:88:3c:87:33:7b:5b:d9:b2:7d:b6:27:a0:ef:5b:95:70:a9:27:97:37:6a:d6:a0:47:55",
              "subject": {
                "organizationalUnitName": "PositiveSSL Multi-Domain",
                "commonName": "sni177528.cloudflaressl.com"
              },
              "subjectPublicKeyInfo": {
                "publicKeySize": 256,
                "publicKeyAlgorithm": "EllipticCurve",
                "publicKey": {
                  "pub": "30:59:30:13:06:07:2a:86:48:ce:3d:02:01:06:08:2a:86:48:ce:3d:03:01:07:03:42:00:04:e5:8e:6b:70:34:fb:ec:1f:30:78:56:64:04:ca:37:ff:7d:12:fc:55:e5:93:f3:c9:85:4c:0e:e4:40:23:e4:6f:20:c0:a5:7b:a9:9d:92:ea:a5:d7:63:ae:13:74:bc:57:88:60:01:d2:96:6c:15:30:33:b3:b8:ae:af:f8:17:ef",
                  "curve": "secp256r1"
                }
              },
              "validity": {
                "notBefore": "Aug 02 00:00:00 2018 GMT",
                "notAfter": "Feb 08 23:59:59 2019 GMT"
              }
            }
          },
          {
            "sha1_fingerprint": "75cfd9bc5cefa104ecc1082d77e63392ccba5291",
            "hpkp_pin": "x9SZw6TwIqfmvrLZ/kz1o0Ossjmn728BnBKpUFqGNVM=",
            "as_pem": "-----BEGIN CERTIFICATE-----\nMIIDnzCCAyWgAwIBAgIQWyXOaQfEJlVm0zkMmalUrTAKBggqhkjOPQQDAzCBhTEL\nMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UE\nBxMHU2FsZm9yZDEaMBgGA1UEChMRQ09NT0RPIENBIExpbWl0ZWQxKzApBgNVBAMT\nIkNPTU9ETyBFQ0MgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMTQwOTI1MDAw\nMDAwWhcNMjkwOTI0MjM1OTU5WjCBkjELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdy\nZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UEBxMHU2FsZm9yZDEaMBgGA1UEChMRQ09N\nT0RPIENBIExpbWl0ZWQxODA2BgNVBAMTL0NPTU9ETyBFQ0MgRG9tYWluIFZhbGlk\nYXRpb24gU2VjdXJlIFNlcnZlciBDQSAyMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcD\nQgAEAjgZgTrJaYRwWQKOqIofMN+83gP8eR06JSxrQSEYgur5PkrkM8wSzypD/A7y\nZADA4SVQgiTNtkk4DyVHkUikraOCAWYwggFiMB8GA1UdIwQYMBaAFHVxpxlIGbyd\nnepBR9+UxEh3mdN5MB0GA1UdDgQWBBRACWFn8LyDcU/eEggsb9TUK3Y9ljAOBgNV\nHQ8BAf8EBAMCAYYwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHSUEFjAUBggrBgEF\nBQcDAQYIKwYBBQUHAwIwGwYDVR0gBBQwEjAGBgRVHSAAMAgGBmeBDAECATBMBgNV\nHR8ERTBDMEGgP6A9hjtodHRwOi8vY3JsLmNvbW9kb2NhLmNvbS9DT01PRE9FQ0ND\nZXJ0aWZpY2F0aW9uQXV0aG9yaXR5LmNybDByBggrBgEFBQcBAQRmMGQwOwYIKwYB\nBQUHMAKGL2h0dHA6Ly9jcnQuY29tb2RvY2EuY29tL0NPTU9ET0VDQ0FkZFRydXN0\nQ0EuY3J0MCUGCCsGAQUFBzABhhlodHRwOi8vb2NzcC5jb21vZG9jYTQuY29tMAoG\nCCqGSM49BAMDA2gAMGUCMQCsaEclgBNPE1bAojcJl1pQxOfttGHLKIoKETKm4nHf\nEQGJbwd6IGZrGNC5LkP3Um8CMBKFfI4TZpIEuppFCZRKMGHRSdxv6+ctyYnPHmp8\n7IXOMCVZuoFwNLg0f+cB0eLLUg==\n-----END CERTIFICATE-----\n",
            "as_dict": {
              "version": 2,
              "extensions": {
                "X509v3 Certificate Policies": {
                  "Policy": [
                    "2.5.29.32.0",
                    "2.23.140.1.2.1"
                  ]
                },
                "X509v3 CRL Distribution Points": {
                  "UniformResourceIdentifier": [],
                  "Full Name": [
                    ""
                  ]
                },
                "X509v3 Basic Constraints": {
                  "pathlen": [
                    "0"
                  ],
                  "CA": [
                    "TRUE"
                  ]
                },
                "X509v3 Authority Key Identifier": "keyid:75:71:a7:19:48:19:bc:9d:9d:ea:41:47:df:94:c4:48:77:99:d3:79",
                "Authority Information Access": {
                  "caIssuers": {
                    "UniformResourceIdentifier": [
                      "http://crt.comodoca.com/COMODOECCAddTrustCA.crt"
                    ]
                  },
                  "OCSP": {
                    "UniformResourceIdentifier": [
                      "http://ocsp.comodoca4.com"
                    ]
                  }
                }
              },
              "issuer": {
                "stateOrProvinceName": "Greater Manchester",
                "organizationName": "COMODO CA Limited",
                "localityName": "Salford",
                "countryName": "GB",
                "commonName": "COMODO ECC Certification Authority"
              },
              "serialNumber": "5B25CE6907C4265566D3390C99A954AD",
              "signatureAlgorithm": "ecdsa-with-SHA384",
              "signatureValue": "30:65:02:31:00:ac:68:47:25:80:13:4f:13:56:c0:a2:37:09:97:5a:50:c4:e7:ed:b4:61:cb:28:8a:0a:11:32:a6:e2:71:df:11:01:89:6f:07:7a:20:66:6b:18:d0:b9:2e:43:f7:52:6f:02:30:12:85:7c:8e:13:66:92:04:ba:9a:45:09:94:4a:30:61:d1:49:dc:6f:eb:e7:2d:c9:89:cf:1e:6a:7c:ec:85:ce:30:25:59:ba:81:70:34:b8:34:7f:e7:01:d1:e2:cb:52",
              "subject": {
                "stateOrProvinceName": "Greater Manchester",
                "organizationName": "COMODO CA Limited",
                "localityName": "Salford",
                "countryName": "GB",
                "commonName": "COMODO ECC Domain Validation Secure Server CA 2"
              },
              "subjectPublicKeyInfo": {
                "publicKeySize": 256,
                "publicKeyAlgorithm": "EllipticCurve",
                "publicKey": {
                  "pub": "30:59:30:13:06:07:2a:86:48:ce:3d:02:01:06:08:2a:86:48:ce:3d:03:01:07:03:42:00:04:02:38:19:81:3a:c9:69:84:70:59:02:8e:a8:8a:1f:30:df:bc:de:03:fc:79:1d:3a:25:2c:6b:41:21:18:82:ea:f9:3e:4a:e4:33:cc:12:cf:2a:43:fc:0e:f2:64:00:c0:e1:25:50:82:24:cd:b6:49:38:0f:25:47:91:48:a4:ad",
                  "curve": "secp256r1"
                }
              },
              "validity": {
                "notBefore": "Sep 25 00:00:00 2014 GMT",
                "notAfter": "Sep 24 23:59:59 2029 GMT"
              }
            }
          },
          {
            "sha1_fingerprint": "9f744e9f2b4dbaec0f312c50b6563b8e2d93c311",
            "hpkp_pin": "58qRu/uxh4gFezqAcERupSkRYBlBAvfcw7mEjGPLnNU=",
            "as_pem": "-----BEGIN CERTIFICATE-----\nMIICiTCCAg+gAwIBAgIQH0evqmIAcFBUTAGem2OZKjAKBggqhkjOPQQDAzCBhTEL\nMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UE\nBxMHU2FsZm9yZDEaMBgGA1UEChMRQ09NT0RPIENBIExpbWl0ZWQxKzApBgNVBAMT\nIkNPTU9ETyBFQ0MgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMDgwMzA2MDAw\nMDAwWhcNMzgwMTE4MjM1OTU5WjCBhTELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdy\nZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UEBxMHU2FsZm9yZDEaMBgGA1UEChMRQ09N\nT0RPIENBIExpbWl0ZWQxKzApBgNVBAMTIkNPTU9ETyBFQ0MgQ2VydGlmaWNhdGlv\nbiBBdXRob3JpdHkwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAQDR3svdcmCFYX7deSR\nFtSrYpn1PlILBs5BAH+X4QokPB0BBO490o0JlwzgdeT6+3eKKvUDYEs2ixYjFq0J\ncfRK9ChQtP6IHG4/bC8vCVlbpVsLM5niwz2J+Wos77LTBumjQjBAMB0GA1UdDgQW\nBBR1cacZSBm8nZ3qQUfflMRId5nTeTAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/\nBAUwAwEB/zAKBggqhkjOPQQDAwNoADBlAjEA7wNbeqy3eApyt4jf/7VGFAkK+qDm\nfQjGGoe9GKhzvSbKYAydzpmfz1wPMOG+FDHqAjAU9JM8SaczepBGR7NjfRObTrdv\nGDeAU/7dIOA1mjbRxwG55tzd8/8dLDoWV9mSOdY=\n-----END CERTIFICATE-----\n",
            "as_dict": {
              "version": 2,
              "extensions": {
                "X509v3 Basic Constraints": {
                  "CA": [
                    "TRUE"
                  ]
                }
              },
              "issuer": {
                "stateOrProvinceName": "Greater Manchester",
                "organizationName": "COMODO CA Limited",
                "localityName": "Salford",
                "countryName": "GB",
                "commonName": "COMODO ECC Certification Authority"
              },
              "serialNumber": "1F47AFAA62007050544C019E9B63992A",
              "signatureAlgorithm": "ecdsa-with-SHA384",
              "signatureValue": "30:65:02:31:00:ef:03:5b:7a:ac:b7:78:0a:72:b7:88:df:ff:b5:46:14:09:0a:fa:a0:e6:7d:08:c6:1a:87:bd:18:a8:73:bd:26:ca:60:0c:9d:ce:99:9f:cf:5c:0f:30:e1:be:14:31:ea:02:30:14:f4:93:3c:49:a7:33:7a:90:46:47:b3:63:7d:13:9b:4e:b7:6f:18:37:80:53:fe:dd:20:e0:35:9a:36:d1:c7:01:b9:e6:dc:dd:f3:ff:1d:2c:3a:16:57:d9:92:39:d6",
              "subject": {
                "stateOrProvinceName": "Greater Manchester",
                "organizationName": "COMODO CA Limited",
                "localityName": "Salford",
                "countryName": "GB",
                "commonName": "COMODO ECC Certification Authority"
              },
              "subjectPublicKeyInfo": {
                "publicKeySize": 384,
                "publicKeyAlgorithm": "EllipticCurve",
                "publicKey": {
                  "pub": "30:76:30:10:06:07:2a:86:48:ce:3d:02:01:06:05:2b:81:04:00:22:03:62:00:04:03:47:7b:2f:75:c9:82:15:85:fb:75:e4:91:16:d4:ab:62:99:f5:3e:52:0b:06:ce:41:00:7f:97:e1:0a:24:3c:1d:01:04:ee:3d:d2:8d:09:97:0c:e0:75:e4:fa:fb:77:8a:2a:f5:03:60:4b:36:8b:16:23:16:ad:09:71:f4:4a:f4:28:50:b4:fe:88:1c:6e:3f:6c:2f:2f:09:59:5b:a5:5b:0b:33:99:e2:c3:3d:89:f9:6a:2c:ef:b2:d3:06:e9",
                  "curve": "secp384r1"
                }
              },
              "validity": {
                "notBefore": "Mar 06 00:00:00 2008 GMT",
                "notAfter": "Jan 18 23:59:59 2038 GMT"
              }
            }
          }
        ],
        "symantec_distrust_timeline": null,
        "successful_trust_store": {
          "version": "2018-06-30",
          "name": "Windows"
        },
        "path_validation_result_list": [
          {
            "verify_string": "ok",
            "trust_store": {
              "version": "8.1.0_r9",
              "name": "Android"
            },
            "is_certificate_trusted": true
          },
          {
            "verify_string": "ok",
            "trust_store": {
              "version": "11",
              "name": "iOS"
            },
            "is_certificate_trusted": true
          },
          {
            "verify_string": "ok",
            "trust_store": {
              "version": "jre-10.0.2",
              "name": "Java"
            },
            "is_certificate_trusted": true
          },
          {
            "verify_string": "ok",
            "trust_store": {
              "version": "High Sierra",
              "name": "macOS"
            },
            "is_certificate_trusted": true
          },
          {
            "verify_string": "ok",
            "trust_store": {
              "version": "2018-04-12",
              "name": "Mozilla"
            },
            "is_certificate_trusted": true
          },
          {
            "verify_string": "ok",
            "trust_store": {
              "version": "2018-06-30",
              "name": "Windows"
            },
            "is_certificate_trusted": true
          }
        ],
        "ocsp_response_status": "SUCCESSFUL",
        "ocsp_response": {
          "version": "1",
          "responses": [
            {
              "thisUpdate": "Aug  6 02:37:19 2018 GMT",
              "nextUpdate": "Aug 13 02:37:19 2018 GMT",
              "certStatus": "good",
              "certID": {
                "serialNumber": "1BCFC52BFCBFCD9A46221503E3146B85",
                "issuerNameHash": "CEA633847FA2C6D73E768EA031C03953C6868E0A",
                "issuerKeyHash": "40096167F0BC83714FDE12082C6FD4D42B763D96",
                "hashAlgorithm": "sha1"
              }
            }
          ],
          "responseType": "Basic OCSP Response",
          "responseStatus": "successful",
          "responderID": "40096167F0BC83714FDE12082C6FD4D42B763D96",
          "producedAt": "Aug  6 02:37:19 2018 GMT"
        },
        "is_ocsp_response_trusted": true,
        "certificate_chain": [
          {
            "sha1_fingerprint": "89aea13db4e38f4095a1ffd6debb27114d27f33a",
            "hpkp_pin": "IaXoxGGXCD8qzLu92R1s2aiO/PlDP67OEEhBcdDLVKM=",
            "as_pem": "-----BEGIN CERTIFICATE-----\nMIIKpjCCCkygAwIBAgIQG8/FK/y/zZpGIhUD4xRrhTAKBggqhkjOPQQDAjCBkjEL\nMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UE\nBxMHU2FsZm9yZDEaMBgGA1UEChMRQ09NT0RPIENBIExpbWl0ZWQxODA2BgNVBAMT\nL0NPTU9ETyBFQ0MgRG9tYWluIFZhbGlkYXRpb24gU2VjdXJlIFNlcnZlciBDQSAy\nMB4XDTE4MDgwMjAwMDAwMFoXDTE5MDIwODIzNTk1OVowbDEhMB8GA1UECxMYRG9t\nYWluIENvbnRyb2wgVmFsaWRhdGVkMSEwHwYDVQQLExhQb3NpdGl2ZVNTTCBNdWx0\naS1Eb21haW4xJDAiBgNVBAMTG3NuaTE3NzUyOC5jbG91ZGZsYXJlc3NsLmNvbTBZ\nMBMGByqGSM49AgEGCCqGSM49AwEHA0IABOWOa3A0++wfMHhWZATKN/99EvxV5ZPz\nyYVMDuRAI+RvIMCle6mdkuql12OuE3S8V4hgAdKWbBUwM7O4rq/4F++jgginMIII\nozAfBgNVHSMEGDAWgBRACWFn8LyDcU/eEggsb9TUK3Y9ljAdBgNVHQ4EFgQUKPuH\nno33C/KtLHm3+Dh1EwveCvAwDgYDVR0PAQH/BAQDAgeAMAwGA1UdEwEB/wQCMAAw\nHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCME8GA1UdIARIMEYwOgYLKwYB\nBAGyMQECAgcwKzApBggrBgEFBQcCARYdaHR0cHM6Ly9zZWN1cmUuY29tb2RvLmNv\nbS9DUFMwCAYGZ4EMAQIBMFYGA1UdHwRPME0wS6BJoEeGRWh0dHA6Ly9jcmwuY29t\nb2RvY2E0LmNvbS9DT01PRE9FQ0NEb21haW5WYWxpZGF0aW9uU2VjdXJlU2VydmVy\nQ0EyLmNybDCBiAYIKwYBBQUHAQEEfDB6MFEGCCsGAQUFBzAChkVodHRwOi8vY3J0\nLmNvbW9kb2NhNC5jb20vQ09NT0RPRUNDRG9tYWluVmFsaWRhdGlvblNlY3VyZVNl\ncnZlckNBMi5jcnQwJQYIKwYBBQUHMAGGGWh0dHA6Ly9vY3NwLmNvbW9kb2NhNC5j\nb20wggXmBgNVHREEggXdMIIF2YIbc25pMTc3NTI4LmNsb3VkZmxhcmVzc2wuY29t\nggkqLjQwZnkuaW+CFSouN3N0YXJob3RlbHMuc2NpZW5jZYIJKi5hdGxzLnRvgg8q\nLmJpbmFyeWVkZ2UuaW+CDCouYm9leXJ0bi5jZoISKi5jYXZpbmd0b3VyLnRyYWRl\ngg8qLmNvZGVhdmVudWUubGuCECouY29udGVudC5zY2hvb2yCDyouY29yc2VjdHJh\nLmNvbYIWKi5jb3p5c2xlZXBvdXRkb29yLmNvbYIRKi5kZXl2YXN0YXRvcnMuZ3GC\nDCouZG1kdmVyaS5ydYINKi5nZXR2ZW5rLmNvbYIMKi5naXp6MTQzLnRrghsqLmd5\nYW5nYW5nYWNoaGluZHdhcmEuY28uaW6CFSouaGFwaGF6YXJkZ291cm1ldC5tbIIR\nKi5ob21lcm9vbS5zY2hvb2yCFCouaG9va2Vkb25jb3VudHJ5Lm1sghoqLmlpc21l\ndWNjaS5hbHRlcnZpc3RhLm9yZ4IJKi5penNlLmNmgg8qLmpveXpvbmUuY28uemGC\nDioubGluZGVob2VrLm5sghAqLmxvYWdxbnJhbmNoLm1sggsqLm1vZmEuYXNpYYIM\nKi5ub3dhbnMuY29tgiAqLnBpenplcmlhLWFsZnJlZG8tb2JlcmhhdXNlbi5kZYIU\nKi5wb3J0Y2l0eXNwb3J0cy5uZXSCEioucHVibGlzaGVyLnNjaG9vbIIUKi5zZXJp\nZWFtb25hbW91ci5jb22CECouc3AtaW1wb3J0cy5jb22CCyouc3BsaWZlLnJ1gg8q\nLnRlcnJqZW5hbHMuZ2GCDioudGhlc2hpZWxkLmlugg0qLnRscmllaGxlLm1sgg0q\nLnRyb3lzaGF3Lm1sghIqLnZpc2l0c3Rsb3Vpcy5jb22CESoudml0YW1hc2hvcXRz\nLmdxghMqLndvcmRwb3dlcmVkLmNvLnVrghUqLndvcmRwcmVzcy1zZW8uY28udWuC\nESoueWF1Z3VhcnNvb2tsLnRrghEqLnl1Z28tZ3JhZG55YS5ydYIRKi56YXRvcHli\nb2h5eXkudGuCBzQwZnkuaW+CEzdzdGFyaG90ZWxzLnNjaWVuY2WCB2F0bHMudG+C\nDWJpbmFyeWVkZ2UuaW+CCmJvZXlydG4uY2aCEGNhdmluZ3RvdXIudHJhZGWCDWNv\nZGVhdmVudWUubGuCDmNvbnRlbnQuc2Nob29sgg1jb3JzZWN0cmEuY29tghRjb3p5\nc2xlZXBvdXRkb29yLmNvbYIPZGV5dmFzdGF0b3JzLmdxggpkbWR2ZXJpLnJ1ggtn\nZXR2ZW5rLmNvbYIKZ2l6ejE0My50a4IZZ3lhbmdhbmdhY2hoaW5kd2FyYS5jby5p\nboITaGFwaGF6YXJkZ291cm1ldC5tbIIPaG9tZXJvb20uc2Nob29sghJob29rZWRv\nbmNvdW50cnkubWyCGGlpc21ldWNjaS5hbHRlcnZpc3RhLm9yZ4IHaXpzZS5jZoIN\nam95em9uZS5jby56YYIMbGluZGVob2VrLm5sgg5sb2FncW5yYW5jaC5tbIIJbW9m\nYS5hc2lhggpub3dhbnMuY29tgh5waXp6ZXJpYS1hbGZyZWRvLW9iZXJoYXVzZW4u\nZGWCEnBvcnRjaXR5c3BvcnRzLm5ldIIQcHVibGlzaGVyLnNjaG9vbIISc2VyaWVh\nbW9uYW1vdXIuY29tgg5zcC1pbXBvcnRzLmNvbYIJc3BsaWZlLnJ1gg10ZXJyamVu\nYWxzLmdhggx0aGVzaGllbGQuaW6CC3RscmllaGxlLm1sggt0cm95c2hhdy5tbIIQ\ndmlzaXRzdGxvdWlzLmNvbYIPdml0YW1hc2hvcXRzLmdxghF3b3JkcG93ZXJlZC5j\nby51a4ITd29yZHByZXNzLXNlby5jby51a4IPeWF1Z3VhcnNvb2tsLnRrgg95dWdv\nLWdyYWRueWEucnWCD3phdG9weWJvaHl5eS50azCCAQQGCisGAQQB1nkCBAIEgfUE\ngfIA8AB3AO5Lvbd1zmC64UJpH6vhnmajD35fsHLYgwDEe4l6qP3LAAABZPh1Db4A\nAAQDAEgwRgIhAKkcUrf+YIQRH4IyWEcM+89Qkhua5KzoxlPrw8xoGg7sAiEAkSDH\nNpZ0GXnbkBlZmg3xKHXHv7ttjG/f7Cl9WK7I5qkAdQB0ftqDMa0zEJEhnM4lT0Jw\nwr/9XkIgCMY3NXnmEHvMVgAAAWT4dQ4ZAAAEAwBGMEQCIAiaiLfYhO3YTHYg6HeR\nk4cdCu7ioXjSDNEjJefJ6INCAiASFSKYBogLGnC6TfmeFmNSw984vxyonew00uxQ\nbeLIdDAKBggqhkjOPQQDAgNIADBFAiBw8N1AtSrs5yQy3cR4ZEtMAfyf5+P2RM5+\neuMIGQ91SQIhAOIex5AxbqqIPIcze1vZsn22J6DvW5VwqSeXN2rWoEdV\n-----END CERTIFICATE-----\n",
            "as_dict": {
              "version": 2,
              "extensions": {
                "X509v3 Certificate Policies": {
                  "Policy": [
                    "1.3.6.1.4.1.6449.1.2.2.7",
                    "2.23.140.1.2.1"
                  ],
                  "CPS": [
                    "https://secure.comodo.com/CPS"
                  ]
                },
                "X509v3 CRL Distribution Points": {
                  "UniformResourceIdentifier": [],
                  "Full Name": [
                    ""
                  ]
                },
                "X509v3 Basic Constraints": {
                  "CA": [
                    "FALSE"
                  ]
                },
                "X509v3 Authority Key Identifier": "keyid:40:09:61:67:f0:bc:83:71:4f:de:12:08:2c:6f:d4:d4:2b:76:3d:96",
                "Authority Information Access": {
                  "caIssuers": {
                    "UniformResourceIdentifier": [
                      "http://crt.comodoca4.com/COMODOECCDomainValidationSecureServerCA2.crt"
                    ]
                  },
                  "OCSP": {
                    "UniformResourceIdentifier": [
                      "http://ocsp.comodoca4.com"
                    ]
                  }
                }
              },
              "issuer": {
                "stateOrProvinceName": "Greater Manchester",
                "organizationName": "COMODO CA Limited",
                "localityName": "Salford",
                "countryName": "GB",
                "commonName": "COMODO ECC Domain Validation Secure Server CA 2"
              },
              "serialNumber": "1BCFC52BFCBFCD9A46221503E3146B85",
              "signatureAlgorithm": "ecdsa-with-SHA256",
              "signatureValue": "30:45:02:20:70:f0:dd:40:b5:2a:ec:e7:24:32:dd:c4:78:64:4b:4c:01:fc:9f:e7:e3:f6:44:ce:7e:7a:e3:08:19:0f:75:49:02:21:00:e2:1e:c7:90:31:6e:aa:88:3c:87:33:7b:5b:d9:b2:7d:b6:27:a0:ef:5b:95:70:a9:27:97:37:6a:d6:a0:47:55",
              "subject": {
                "organizationalUnitName": "PositiveSSL Multi-Domain",
                "commonName": "sni177528.cloudflaressl.com"
              },
              "subjectPublicKeyInfo": {
                "publicKeySize": 256,
                "publicKeyAlgorithm": "EllipticCurve",
                "publicKey": {
                  "pub": "30:59:30:13:06:07:2a:86:48:ce:3d:02:01:06:08:2a:86:48:ce:3d:03:01:07:03:42:00:04:e5:8e:6b:70:34:fb:ec:1f:30:78:56:64:04:ca:37:ff:7d:12:fc:55:e5:93:f3:c9:85:4c:0e:e4:40:23:e4:6f:20:c0:a5:7b:a9:9d:92:ea:a5:d7:63:ae:13:74:bc:57:88:60:01:d2:96:6c:15:30:33:b3:b8:ae:af:f8:17:ef",
                  "curve": "secp256r1"
                }
              },
              "validity": {
                "notBefore": "Aug 02 00:00:00 2018 GMT",
                "notAfter": "Feb 08 23:59:59 2019 GMT"
              }
            }
          },
          {
            "sha1_fingerprint": "75cfd9bc5cefa104ecc1082d77e63392ccba5291",
            "hpkp_pin": "x9SZw6TwIqfmvrLZ/kz1o0Ossjmn728BnBKpUFqGNVM=",
            "as_pem": "-----BEGIN CERTIFICATE-----\nMIIDnzCCAyWgAwIBAgIQWyXOaQfEJlVm0zkMmalUrTAKBggqhkjOPQQDAzCBhTEL\nMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UE\nBxMHU2FsZm9yZDEaMBgGA1UEChMRQ09NT0RPIENBIExpbWl0ZWQxKzApBgNVBAMT\nIkNPTU9ETyBFQ0MgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMTQwOTI1MDAw\nMDAwWhcNMjkwOTI0MjM1OTU5WjCBkjELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdy\nZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UEBxMHU2FsZm9yZDEaMBgGA1UEChMRQ09N\nT0RPIENBIExpbWl0ZWQxODA2BgNVBAMTL0NPTU9ETyBFQ0MgRG9tYWluIFZhbGlk\nYXRpb24gU2VjdXJlIFNlcnZlciBDQSAyMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcD\nQgAEAjgZgTrJaYRwWQKOqIofMN+83gP8eR06JSxrQSEYgur5PkrkM8wSzypD/A7y\nZADA4SVQgiTNtkk4DyVHkUikraOCAWYwggFiMB8GA1UdIwQYMBaAFHVxpxlIGbyd\nnepBR9+UxEh3mdN5MB0GA1UdDgQWBBRACWFn8LyDcU/eEggsb9TUK3Y9ljAOBgNV\nHQ8BAf8EBAMCAYYwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHSUEFjAUBggrBgEF\nBQcDAQYIKwYBBQUHAwIwGwYDVR0gBBQwEjAGBgRVHSAAMAgGBmeBDAECATBMBgNV\nHR8ERTBDMEGgP6A9hjtodHRwOi8vY3JsLmNvbW9kb2NhLmNvbS9DT01PRE9FQ0ND\nZXJ0aWZpY2F0aW9uQXV0aG9yaXR5LmNybDByBggrBgEFBQcBAQRmMGQwOwYIKwYB\nBQUHMAKGL2h0dHA6Ly9jcnQuY29tb2RvY2EuY29tL0NPTU9ET0VDQ0FkZFRydXN0\nQ0EuY3J0MCUGCCsGAQUFBzABhhlodHRwOi8vb2NzcC5jb21vZG9jYTQuY29tMAoG\nCCqGSM49BAMDA2gAMGUCMQCsaEclgBNPE1bAojcJl1pQxOfttGHLKIoKETKm4nHf\nEQGJbwd6IGZrGNC5LkP3Um8CMBKFfI4TZpIEuppFCZRKMGHRSdxv6+ctyYnPHmp8\n7IXOMCVZuoFwNLg0f+cB0eLLUg==\n-----END CERTIFICATE-----\n",
            "as_dict": {
              "version": 2,
              "extensions": {
                "X509v3 Certificate Policies": {
                  "Policy": [
                    "2.5.29.32.0",
                    "2.23.140.1.2.1"
                  ]
                },
                "X509v3 CRL Distribution Points": {
                  "UniformResourceIdentifier": [],
                  "Full Name": [
                    ""
                  ]
                },
                "X509v3 Basic Constraints": {
                  "pathlen": [
                    "0"
                  ],
                  "CA": [
                    "TRUE"
                  ]
                },
                "X509v3 Authority Key Identifier": "keyid:75:71:a7:19:48:19:bc:9d:9d:ea:41:47:df:94:c4:48:77:99:d3:79",
                "Authority Information Access": {
                  "caIssuers": {
                    "UniformResourceIdentifier": [
                      "http://crt.comodoca.com/COMODOECCAddTrustCA.crt"
                    ]
                  },
                  "OCSP": {
                    "UniformResourceIdentifier": [
                      "http://ocsp.comodoca4.com"
                    ]
                  }
                }
              },
              "issuer": {
                "stateOrProvinceName": "Greater Manchester",
                "organizationName": "COMODO CA Limited",
                "localityName": "Salford",
                "countryName": "GB",
                "commonName": "COMODO ECC Certification Authority"
              },
              "serialNumber": "5B25CE6907C4265566D3390C99A954AD",
              "signatureAlgorithm": "ecdsa-with-SHA384",
              "signatureValue": "30:65:02:31:00:ac:68:47:25:80:13:4f:13:56:c0:a2:37:09:97:5a:50:c4:e7:ed:b4:61:cb:28:8a:0a:11:32:a6:e2:71:df:11:01:89:6f:07:7a:20:66:6b:18:d0:b9:2e:43:f7:52:6f:02:30:12:85:7c:8e:13:66:92:04:ba:9a:45:09:94:4a:30:61:d1:49:dc:6f:eb:e7:2d:c9:89:cf:1e:6a:7c:ec:85:ce:30:25:59:ba:81:70:34:b8:34:7f:e7:01:d1:e2:cb:52",
              "subject": {
                "stateOrProvinceName": "Greater Manchester",
                "organizationName": "COMODO CA Limited",
                "localityName": "Salford",
                "countryName": "GB",
                "commonName": "COMODO ECC Domain Validation Secure Server CA 2"
              },
              "subjectPublicKeyInfo": {
                "publicKeySize": 256,
                "publicKeyAlgorithm": "EllipticCurve",
                "publicKey": {
                  "pub": "30:59:30:13:06:07:2a:86:48:ce:3d:02:01:06:08:2a:86:48:ce:3d:03:01:07:03:42:00:04:02:38:19:81:3a:c9:69:84:70:59:02:8e:a8:8a:1f:30:df:bc:de:03:fc:79:1d:3a:25:2c:6b:41:21:18:82:ea:f9:3e:4a:e4:33:cc:12:cf:2a:43:fc:0e:f2:64:00:c0:e1:25:50:82:24:cd:b6:49:38:0f:25:47:91:48:a4:ad",
                  "curve": "secp256r1"
                }
              },
              "validity": {
                "notBefore": "Sep 25 00:00:00 2014 GMT",
                "notAfter": "Sep 24 23:59:59 2029 GMT"
              }
            }
          },
          {
            "sha1_fingerprint": "ae223cbf20191b40d7ffb4ea5701b65fdc68a1ca",
            "hpkp_pin": "58qRu/uxh4gFezqAcERupSkRYBlBAvfcw7mEjGPLnNU=",
            "as_pem": "-----BEGIN CERTIFICATE-----\nMIID0DCCArigAwIBAgIQQ1ICP/qokB8Tn+P05cFETjANBgkqhkiG9w0BAQwFADBv\nMQswCQYDVQQGEwJTRTEUMBIGA1UEChMLQWRkVHJ1c3QgQUIxJjAkBgNVBAsTHUFk\nZFRydXN0IEV4dGVybmFsIFRUUCBOZXR3b3JrMSIwIAYDVQQDExlBZGRUcnVzdCBF\neHRlcm5hbCBDQSBSb290MB4XDTAwMDUzMDEwNDgzOFoXDTIwMDUzMDEwNDgzOFow\ngYUxCzAJBgNVBAYTAkdCMRswGQYDVQQIExJHcmVhdGVyIE1hbmNoZXN0ZXIxEDAO\nBgNVBAcTB1NhbGZvcmQxGjAYBgNVBAoTEUNPTU9ETyBDQSBMaW1pdGVkMSswKQYD\nVQQDEyJDT01PRE8gRUNDIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MHYwEAYHKoZI\nzj0CAQYFK4EEACIDYgAEA0d7L3XJghWF+3XkkRbUq2KZ9T5SCwbOQQB/l+EKJDwd\nAQTuPdKNCZcM4HXk+vt3iir1A2BLNosWIxatCXH0SvQoULT+iBxuP2wvLwlZW6Vb\nCzOZ4sM9iflqLO+y0wbpo4H+MIH7MB8GA1UdIwQYMBaAFK29mHo0tCb3+sQmVO8D\nveAky1QaMB0GA1UdDgQWBBR1cacZSBm8nZ3qQUfflMRId5nTeTAOBgNVHQ8BAf8E\nBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zARBgNVHSAECjAIMAYGBFUdIAAwSQYDVR0f\nBEIwQDA+oDygOoY4aHR0cDovL2NybC50cnVzdC1wcm92aWRlci5jb20vQWRkVHJ1\nc3RFeHRlcm5hbENBUm9vdC5jcmwwOgYIKwYBBQUHAQEELjAsMCoGCCsGAQUFBzAB\nhh5odHRwOi8vb2NzcC50cnVzdC1wcm92aWRlci5jb20wDQYJKoZIhvcNAQEMBQAD\nggEBAB3H+i5AtlwFSw+8VTYBWOBTBT1k+6zZpTi4pyE7r5VbvkjI00PUIWxB7Qkt\nnHMAcZyuIXN+/46NuY5YkI78jG12yAA6nyCmLX3MF/3NmJYyCRrJZfwE67SaCnjl\nlztSjxLCdJcBns/hbWjYk7mcJPuWJ0gBnOqUP3CYQbNzUTcp6PYBerknuCRR2RFo\n1KaFpzanpZa6gPim/a5thCCuNXZzQg+HCezF3OeTAyIal+6ailFhp5cmHunudVEI\nkAWvL54TnJM/ev/m6+loeYyv4Lb67psSE/5FjNJ80zXrIRKT/mZ1JioVhCb3ZsnL\njbsJQdQYr7GzEPUQyp2aDrV1aug=\n-----END CERTIFICATE-----\n",
            "as_dict": {
              "version": 2,
              "extensions": {
                "X509v3 Certificate Policies": {
                  "Policy": [
                    "2.5.29.32.0"
                  ]
                },
                "X509v3 CRL Distribution Points": {
                  "UniformResourceIdentifier": [],
                  "Full Name": [
                    ""
                  ]
                },
                "X509v3 Basic Constraints": {
                  "CA": [
                    "TRUE"
                  ]
                },
                "X509v3 Authority Key Identifier": "keyid:ad:bd:98:7a:34:b4:26:f7:fa:c4:26:54:ef:03:bd:e0:24:cb:54:1a",
                "Authority Information Access": {
                  "OCSP": {
                    "UniformResourceIdentifier": [
                      "http://ocsp.trust-provider.com"
                    ]
                  }
                }
              },
              "issuer": {
                "organizationalUnitName": "AddTrust External TTP Network",
                "organizationName": "AddTrust AB",
                "countryName": "SE",
                "commonName": "AddTrust External CA Root"
              },
              "serialNumber": "4352023FFAA8901F139FE3F4E5C1444E",
              "signatureAlgorithm": "sha384WithRSAEncryption",
              "signatureValue": "1d:c7:fa:2e:40:b6:5c:05:4b:0f:bc:55:36:01:58:e0:53:05:3d:64:fb:ac:d9:a5:38:b8:a7:21:3b:af:95:5b:be:48:c8:d3:43:d4:21:6c:41:ed:09:2d:9c:73:00:71:9c:ae:21:73:7e:ff:8e:8d:b9:8e:58:90:8e:fc:8c:6d:76:c8:00:3a:9f:20:a6:2d:7d:cc:17:fd:cd:98:96:32:09:1a:c9:65:fc:04:eb:b4:9a:0a:78:e5:97:3b:52:8f:12:c2:74:97:01:9e:cf:e1:6d:68:d8:93:b9:9c:24:fb:96:27:48:01:9c:ea:94:3f:70:98:41:b3:73:51:37:29:e8:f6:01:7a:b9:27:b8:24:51:d9:11:68:d4:a6:85:a7:36:a7:a5:96:ba:80:f8:a6:fd:ae:6d:84:20:ae:35:76:73:42:0f:87:09:ec:c5:dc:e7:93:03:22:1a:97:ee:9a:8a:51:61:a7:97:26:1e:e9:ee:75:51:08:90:05:af:2f:9e:13:9c:93:3f:7a:ff:e6:eb:e9:68:79:8c:af:e0:b6:fa:ee:9b:12:13:fe:45:8c:d2:7c:d3:35:eb:21:12:93:fe:66:75:26:2a:15:84:26:f7:66:c9:cb:8d:bb:09:41:d4:18:af:b1:b3:10:f5:10:ca:9d:9a:0e:b5:75:6a:e8",
              "subject": {
                "stateOrProvinceName": "Greater Manchester",
                "organizationName": "COMODO CA Limited",
                "localityName": "Salford",
                "countryName": "GB",
                "commonName": "COMODO ECC Certification Authority"
              },
              "subjectPublicKeyInfo": {
                "publicKeySize": 384,
                "publicKeyAlgorithm": "EllipticCurve",
                "publicKey": {
                  "pub": "30:76:30:10:06:07:2a:86:48:ce:3d:02:01:06:05:2b:81:04:00:22:03:62:00:04:03:47:7b:2f:75:c9:82:15:85:fb:75:e4:91:16:d4:ab:62:99:f5:3e:52:0b:06:ce:41:00:7f:97:e1:0a:24:3c:1d:01:04:ee:3d:d2:8d:09:97:0c:e0:75:e4:fa:fb:77:8a:2a:f5:03:60:4b:36:8b:16:23:16:ad:09:71:f4:4a:f4:28:50:b4:fe:88:1c:6e:3f:6c:2f:2f:09:59:5b:a5:5b:0b:33:99:e2:c3:3d:89:f9:6a:2c:ef:b2:d3:06:e9",
                  "curve": "secp384r1"
                }
              },
              "validity": {
                "notBefore": "May 30 10:48:38 2000 GMT",
                "notAfter": "May 30 10:48:38 2020 GMT"
              }
            }
          }
        ],
        "certificate_has_must_staple_extension": false,
        "certificate_included_scts_count": 2,
        "certificate_matches_hostname": true,
        "has_anchor_in_certificate_chain": false,
        "has_sha1_in_certificate_chain": false,
        "is_certificate_chain_order_valid": true,
        "is_leaf_certificate_ev": false
      }
    }
  },
  ...
}
```
