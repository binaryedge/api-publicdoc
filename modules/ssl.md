# SSL

SSL Module can analyze the SSL configuration of a server by connecting to it.
It is designed to be fast and comprehensive and should help organizations and testers identify misconfigurations affecting their SSL servers.

By default, the SSL module runs in full mode, where it will run all the cipher suite tests. It is possible to disable the cipher tests by selecting the fast mode, i.e., changing the configuration key **ssl_mode** to **fast**.

## SSL Request Example

```
curl -v -L https://api.binaryedge.io/v1/tasks -d '{"type":"scan", "options":[{"targets":["X.X.X.X"], "ports":[{"port":443, "protocol":"tcp", "modules":["ssl"], "config":{}}]}]}' -H "X-Token:<Token>"
```

### SSL Request Options

These are optional parameters that can alter the behaviour of the module. These options can be inserted into the "config" object on the request.

  * sni - set HTTPS Server Name Indication
    * "config":{"sni":"google.com"}
  * ssl_mode - disable the cipher tests
    * "config":{"ssl_mode":"fast"}

## Schema

### SSL Event Schema

```json
{
  ...
  "result": {
    "data": {
      "truststores": [
        {
          "is_certificate_trusted": "true",
          "trust_store": {
            "_certificate_list": null,
            "name": "string",
            "version": "string"
          },
          "verify_string": "string"
        },
        ...
      ],
      "ciphers": {
        "tlsv1_2": {
          "errored_cipher_list": [],
          "preferred_cipher": {
            "is_anonymous": "boolean",
            "name": "string",
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
              "is_anonymous": "boolean",
              "name": "string",
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
          "plugin_options": {},
          "accepts_client_renegotiation": "boolean",
          "supports_secure_renegotiation": "boolean"
        },
        "compression": {
          "supports_compression": "boolean"
        },
        "fallback": {
          "plugin_options": {},
          "supports_fallback_scsv": "boolean"
        }
      },
      "cert_info": {
        "ocsp_response": {},
        "is_certificate_chain_order_valid": "boolean",
        "hostname_validation_result": "int",
        "is_leaf_certificate_ev": "boolean",
        "is_ocsp_response_trusted": "boolean",
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
                  "exponent": "string"
                }
              },
              "validity": {
                "notAfter": "string",
                "notBefore": "string"
              },
              "version": "int",
              "issuer": {
                "commonName": "string",
                "organizationName": "string",
                "countryName": "string"
              },
              "signatureAlgorithm": "string",
              "signatureValue": "string"
            },
            "sha1_fingerprint": "string",
            "as_pem": "string"
          },
          ...
        ],
        "path_validation_result_list": [
          {
            "is_certificate_trusted": "boolean",
            "trust_store": {
              "_certificate_list": null,
              "name": "string",
              "version": "string"
            },
            "verify_string": "string"
          },
          ...
        ]
      },
      "server_info": {
        "ssl_cipher_supported": "string",
        "hostname": "string",
        "client_auth_requirement": "int",
        "highest_ssl_version_supported": "int",
        "port": "int",
        "http_tunneling_settings": {},
        "ip_address": "string",
        "client_auth_credentials": {},
        "tls_wrapped_protocol": "int",
        "xmpp_to_hostname": "string",
        "tls_server_name_indication": "string"
      }
    }
  },
}
```

### Contents of the fields:

*Variables description from https://nabla-c0d3.github.io/sslyze/documentation/available-scan-commands.html, https://github.com/nabla-c0d3/sslyze/blob/master/sslyze/server_connectivity.py and https://godoc.org/github.com/lair-framework/go-sslyze*

* truststores - a set of root certificates to be used for certificate validation
  * is_certificate_trusted - whether the certificate chain is trusted when using supplied the trust_store
  * trust_store - the trust store used for validation
    * name - the human-readable name of the trust store
    * version - the human-readable version or date of the trust store
  * verify_string - the string returned by OpenSSL’s validation function
* ciphers - The result of running a CipherSuiteScanCommand on a specific server. Note: independently of the type of cipher and cipher_list, they all have the same fields. So, in order to simplify, we will only describe one of each
  * tlsv1_1/ tlsv1_2/ sslv2/ sslv3 - versions of the ssl
    * errored_cipher_list - the list of cipher suites supported that triggered an unexpected error during the TLS handshake with the server
    * preferred_cipher - the server’s preferred cipher suite among all the cipher suites supported. None if the server follows the client’s preference or if none of the tool's cipher suites are supported by the server
    * accepted_cipher_list - the list of cipher suites supported by both the tool and the server
      * is_anonymous - true if the cipher suite is an anonymous cipher suite (ie. no server authentication)
      * name -  the cipher suite’s RFC name
      * post_handshake_response - the server’s response after completing the SSL/TLS handshake and sending a request, based on the TlsWrappedProtocolEnum set for this server. For example, this will contain an HTTP response when scanning an HTTPS server with TlsWrappedProtocolEnum.HTTPS as the tls_wrapped_protocol
      * dh_info - additional details about the Diffie Helmann parameters for DH and ECDH cipher suites. None if the cipher suite is not DH or ECDH
      * key_size - the key size of the cipher suite’s algorithm in bits
* vulnerabilities - information about SSL vulnerabilities
  * openssl_ccs - test the server(s) for the OpenSSL CCS injection vulnerability
    * is_vulnerable_to_ccs_injection - true if the server is vulnerable to OpenSSL’s CCS injection issue
  * heartbleed - test the server(s) for the OpenSSL Heartbleed vulnerability
    * is_vulnerable_to_heartbleed - True if the server is vulnerable to the Heartbleed attack
  * renegotiation - test the server(s) for client-initiated renegotiation and secure renegotiation support
    * plugin_options - plugin options
    * accepts_client_renegotiation - true if the server honors client-initiated renegotiation attempts
    * supports_secure_renegotiation - true if the server supports secure renegotiation
  * compression - test the server(s) for Zlib compression support
    * supports_compression - true if the server supports compression
  * fallback - test the server(s) for support of the TLS_FALLBACK_SCSV cipher suite which prevents downgrade attacks
    * plugin_options - plugin options
    * supports_fallback_scsv - true if the server supports the TLS_FALLBACK_SCSV mechanism to block downgrade
* cert_info - verify the validity of the server(s) certificate(s) against various trust stores (Mozilla, Apple, etc.), and check for OCSP stapling support
  * ocsp_response - the OCSP response returned by the server. None if no response was sent by the server
  * is_certificate_chain_order_valid - true if the order of the certificate chain is valid
  * hostname_validation_result - validation result of the certificate hostname
  * is_leaf_certificate_ev - true if the leaf certificate is Extended Validation according to Mozilla
  * is_ocsp_response_trusted - true if the OCSP response is trusted using the Mozilla trust store. None if no OCSP response was sent by the server
  * certificate_chain - the certificate chain sent by the server; index 0 is the leaf certificate
    * as_dict
      * extensions - Extension contains the target's certificate extensions
      * serialNumber - the certificate serial number
      * subject - subject contains the target's certificate subject information
        * commonName - common name of the subject
        * localityName - locality of the subject
        * organizationName - name of the organization of the subject
        * organizationalUnitName - organizational unit name of the subject
        * countryName - country of the subject
        * stateOrProvinceName - state or province of the subject
      * subjectPublicKeyInfo - contains information about the public key stored in the certificate
        * publicKeyAlgorithm - algorithm used to create the public key
        * publicKeySize - size of the public key
        * publicKey - contains the target public key
          * modulus - returns the value of attribute modulus
          * exponent - returns the value of attribute exponent.
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
      * as_pem - the certificate in PEM format
  * path_validation_result_list - the list of attempts at validating the server’s certificate chain path using the trust stores packaged (Mozilla, Apple, etc.)
    * is_certificate_trusted - whether the certificate chain is trusted when using supplied the trust_store
    * trust_store - the trust store used for validation
      * name - the human-readable name of the trust store
      * version - the human-readable version or date of the trust store
    * verify_string - the string returned by OpenSSL’s validation function
* server_info - the server against which the command was run
  * ssl_cipher_supported - list of ssl ciphers supported by the server
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

## SSL Event Example

### Request

```
curl https://api.binaryedge.io/v1/tasks -d '{"type":"scan", "description": "SSL Request", "options":[{"targets":["X.X.X.X"], "ports":[{"port":"443", "protocol":"tcp", "modules": ["ssl"], "config":{"sni":"www.binaryedge.io", "ssl_mode":"full"}}]}]}' -H "X-Token:<Token>"
```

### Response

```json
{
  ...
  "result": {
    "data": {
      "truststores": [
        {
          "is_certificate_trusted": true,
          "trust_store": {
            "_certificate_list": null,
            "name": "Mozilla NSS",
            "version": "02/2016"
          },
          "verify_string": "ok"
        },
        {
          "is_certificate_trusted": true,
          "trust_store": {
            "_certificate_list": null,
            "name": "Microsoft",
            "version": "02/2016"
          },
          "verify_string": "ok"
        },
        {
          "is_certificate_trusted": true,
          "trust_store": {
            "_certificate_list": null,
            "name": "Apple",
            "version": "OS X 10.11.3"
          },
          "verify_string": "ok"
        },
        {
          "is_certificate_trusted": true,
          "trust_store": {
            "_certificate_list": null,
            "name": "Java 7",
            "version": "Update 79"
          },
          "verify_string": "ok"
        },
        {
          "is_certificate_trusted": true,
          "trust_store": {
            "_certificate_list": null,
            "name": "AOSP",
            "version": "N Preview 2"
          },
          "verify_string": "ok"
        }
      ],
      "ciphers": {
        "tlsv1_2": {
          "errored_cipher_list": [],
          "preferred_cipher": {
            "is_anonymous": false,
            "name": "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
            "post_handshake_response": "",
            "dh_info": {
              "Order": "0x00ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
              "A": "0x00ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
              "B": "0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
              "Type": "ECDH",
              "Prime": "0x00ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
              "Seed": "0xc49d360886e704936a6678e1139d26b7819f7e90",
              "Field_Type": "prime-field",
              "Cofactor": "1",
              "GroupSize": "256",
              "Generator": "0x046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
              "GeneratorType": "uncompressed"
            },
            "key_size": 256
          },
          "accepted_cipher_list": [
            {
              "is_anonymous": false,
              "name": "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
              "post_handshake_response": "",
              "dh_info": {
                "Order": "0x00ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
                "A": "0x00ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
                "B": "0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
                "Type": "ECDH",
                "Prime": "0x00ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
                "Seed": "0xc49d360886e704936a6678e1139d26b7819f7e90",
                "Field_Type": "prime-field",
                "Cofactor": "1",
                "GroupSize": "256",
                "Generator": "0x046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
                "GeneratorType": "uncompressed"
              },
              "key_size": 256
            },
            {
              "is_anonymous": false,
              "name": "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
              "post_handshake_response": "",
              "dh_info": {
                "Order": "0x00ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
                "A": "0x00ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
                "B": "0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
                "Type": "ECDH",
                "Prime": "0x00ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
                "Seed": "0xc49d360886e704936a6678e1139d26b7819f7e90",
                "Field_Type": "prime-field",
                "Cofactor": "1",
                "GroupSize": "256",
                "Generator": "0x046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
                "GeneratorType": "uncompressed"
              },
              "key_size": 256
            },
            {
              "is_anonymous": false,
              "name": "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
              "post_handshake_response": "",
              "dh_info": {
                "Order": "0x00ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
                "A": "0x00ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
                "B": "0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
                "Type": "ECDH",
                "Prime": "0x00ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
                "Seed": "0xc49d360886e704936a6678e1139d26b7819f7e90",
                "Field_Type": "prime-field",
                "Cofactor": "1",
                "GroupSize": "256",
                "Generator": "0x046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
                "GeneratorType": "uncompressed"
              },
              "key_size": 256
            },
            {
              "is_anonymous": false,
              "name": "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
              "post_handshake_response": "",
              "dh_info": {
                "Order": "0x00ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
                "A": "0x00ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
                "B": "0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
                "Type": "ECDH",
                "Prime": "0x00ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
                "Seed": "0xc49d360886e704936a6678e1139d26b7819f7e90",
                "Field_Type": "prime-field",
                "Cofactor": "1",
                "GroupSize": "256",
                "Generator": "0x046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
                "GeneratorType": "uncompressed"
              },
              "key_size": 256
            },
            {
              "is_anonymous": false,
              "name": "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
              "post_handshake_response": "",
              "dh_info": {
                "Order": "0x00ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
                "A": "0x00ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
                "B": "0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
                "Type": "ECDH",
                "Prime": "0x00ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
                "Seed": "0xc49d360886e704936a6678e1139d26b7819f7e90",
                "Field_Type": "prime-field",
                "Cofactor": "1",
                "GroupSize": "256",
                "Generator": "0x046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
                "GeneratorType": "uncompressed"
              },
              "key_size": 128
            },
            {
              "is_anonymous": false,
              "name": "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
              "post_handshake_response": "",
              "dh_info": {
                "Order": "0x00ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
                "A": "0x00ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
                "B": "0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
                "Type": "ECDH",
                "Prime": "0x00ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
                "Seed": "0xc49d360886e704936a6678e1139d26b7819f7e90",
                "Field_Type": "prime-field",
                "Cofactor": "1",
                "GroupSize": "256",
                "Generator": "0x046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
                "GeneratorType": "uncompressed"
              },
              "key_size": 128
            },
            {
              "is_anonymous": false,
              "name": "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
              "post_handshake_response": "",
              "dh_info": {
                "Order": "0x00ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
                "A": "0x00ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
                "B": "0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
                "Type": "ECDH",
                "Prime": "0x00ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
                "Seed": "0xc49d360886e704936a6678e1139d26b7819f7e90",
                "Field_Type": "prime-field",
                "Cofactor": "1",
                "GroupSize": "256",
                "Generator": "0x046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
                "GeneratorType": "uncompressed"
              },
              "key_size": 128
            }
          ]
        },
        "tlsv1_1": {
          "errored_cipher_list": [],
          "preferred_cipher": {
            "is_anonymous": false,
            "name": "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
            "post_handshake_response": "",
            "dh_info": {
              "Order": "0x00ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
              "A": "0x00ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
              "B": "0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
              "Type": "ECDH",
              "Prime": "0x00ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
              "Seed": "0xc49d360886e704936a6678e1139d26b7819f7e90",
              "Field_Type": "prime-field",
              "Cofactor": "1",
              "GroupSize": "256",
              "Generator": "0x046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
              "GeneratorType": "uncompressed"
            },
            "key_size": 128
          },
          "accepted_cipher_list": [
            {
              "is_anonymous": false,
              "name": "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
              "post_handshake_response": "",
              "dh_info": {
                "Order": "0x00ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
                "A": "0x00ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
                "B": "0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
                "Type": "ECDH",
                "Prime": "0x00ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
                "Seed": "0xc49d360886e704936a6678e1139d26b7819f7e90",
                "Field_Type": "prime-field",
                "Cofactor": "1",
                "GroupSize": "256",
                "Generator": "0x046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
                "GeneratorType": "uncompressed"
              },
              "key_size": 256
            },
            {
              "is_anonymous": false,
              "name": "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
              "post_handshake_response": "",
              "dh_info": {
                "Order": "0x00ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
                "A": "0x00ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
                "B": "0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
                "Type": "ECDH",
                "Prime": "0x00ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
                "Seed": "0xc49d360886e704936a6678e1139d26b7819f7e90",
                "Field_Type": "prime-field",
                "Cofactor": "1",
                "GroupSize": "256",
                "Generator": "0x046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
                "GeneratorType": "uncompressed"
              },
              "key_size": 128
            }
          ]
        },
        "sslv2": {
          "errored_cipher_list": [],
          "preferred_cipher": null,
          "accepted_cipher_list": []
        },
        "sslv3": {
          "errored_cipher_list": [],
          "preferred_cipher": null,
          "accepted_cipher_list": []
        },
        "tlsv1": {
          "errored_cipher_list": [],
          "preferred_cipher": {
            "is_anonymous": false,
            "name": "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
            "post_handshake_response": "",
            "dh_info": {
              "Order": "0x00ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
              "A": "0x00ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
              "B": "0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
              "Type": "ECDH",
              "Prime": "0x00ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
              "Seed": "0xc49d360886e704936a6678e1139d26b7819f7e90",
              "Field_Type": "prime-field",
              "Cofactor": "1",
              "GroupSize": "256",
              "Generator": "0x046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
              "GeneratorType": "uncompressed"
            },
            "key_size": 128
          },
          "accepted_cipher_list": [
            {
              "is_anonymous": false,
              "name": "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
              "post_handshake_response": "",
              "dh_info": {
                "Order": "0x00ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
                "A": "0x00ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
                "B": "0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
                "Type": "ECDH",
                "Prime": "0x00ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
                "Seed": "0xc49d360886e704936a6678e1139d26b7819f7e90",
                "Field_Type": "prime-field",
                "Cofactor": "1",
                "GroupSize": "256",
                "Generator": "0x046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
                "GeneratorType": "uncompressed"
              },
              "key_size": 256
            },
            {
              "is_anonymous": false,
              "name": "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
              "post_handshake_response": "",
              "dh_info": {
                "Order": "0x00ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
                "A": "0x00ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
                "B": "0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
                "Type": "ECDH",
                "Prime": "0x00ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
                "Seed": "0xc49d360886e704936a6678e1139d26b7819f7e90",
                "Field_Type": "prime-field",
                "Cofactor": "1",
                "GroupSize": "256",
                "Generator": "0x046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
                "GeneratorType": "uncompressed"
              },
              "key_size": 128
            },
            {
              "is_anonymous": false,
              "name": "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
              "post_handshake_response": "",
              "dh_info": {
                "Order": "0x00ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
                "A": "0x00ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
                "B": "0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
                "Type": "ECDH",
                "Prime": "0x00ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
                "Seed": "0xc49d360886e704936a6678e1139d26b7819f7e90",
                "Field_Type": "prime-field",
                "Cofactor": "1",
                "GroupSize": "256",
                "Generator": "0x046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
                "GeneratorType": "uncompressed"
              },
              "key_size": 112
            }
          ]
        }
      },
      "vulnerabilities": {
        "openssl_ccs": {
          "is_vulnerable_to_ccs_injection": false
        },
        "heartbleed": {
          "is_vulnerable_to_heartbleed": false
        },
        "renegotiation": {
          "plugin_options": {},
          "accepts_client_renegotiation": false,
          "supports_secure_renegotiation": true
        },
        "compression": {
          "supports_compression": false
        },
        "fallback": {
          "plugin_options": {},
          "supports_fallback_scsv": true
        }
      },
      "cert_info": {
        "ocsp_response": null,
        "is_certificate_chain_order_valid": true,
        "hostname_validation_result": 1,
        "is_leaf_certificate_ev": false,
        "is_ocsp_response_trusted": false,
        "certificate_chain": [
          {
            "as_dict": {
              "extensions": {
                "X509v3 Authority Key Identifier": "keyid:40:09:61:67:F0:BC:83:71:4F:DE:12:08:2C:6F:D4:D4:2B:76:3D:96",
                "X509v3 Certificate Policies": {
                  "Policy": [
                    "1.3.6.1.4.1.6449.1.2.2.7",
                    "2.23.140.1.2.1"
                  ],
                  "CPS": [
                    "https://secure.comodo.com/CPS"
                  ]
                },
                "Authority Information Access": {
                  "OCSP": {
                    "URI": [
                      "http://ocsp.comodoca4.com"
                    ]
                  },
                  "CAIssuers": {
                    "URI": [
                      "http://crt.comodoca4.com/COMODOECCDomainValidationSecureServerCA2.crt"
                    ]
                  }
                },
                "X509v3 Basic Constraints": {
                  "CA": [
                    "FALSE"
                  ]
                },
                "X509v3 Key Usage": {
                  "Digital Signature": ""
                },
                "X509v3 Extended Key Usage": {
                  "TLS Web Server Authentication": "",
                  "TLS Web Client Authentication": ""
                },
                "X509v3 Subject Key Identifier": "28:FB:87:9E:8D:F7:0B:F2:AD:2C:79:B7:F8:38:75:13:0B:DE:0A:F0",
                "X509v3 CRL Distribution Points": {
                  "Full Name": [
                    ""
                  ],
                  "URI": [
                    "http://crl.comodoca4.com/COMODOECCDomainValidationSecureServerCA2.crl"
                  ]
                },
                "X509v3 Subject Alternative Name": {
                  "DNS": [
                    "sni177528.cloudflaressl.com",
                    "*.40fy.io",
                    "*.anyhead.xyz",
                    "*.binaryedge.io",
                    "*.ccraftedstudio.tk",
                    "*.chiccomfort.ru",
                    "*.content.school",
                    "*.cozysleepoutdoor.com",
                    "*.fullstar.tk",
                    "*.greenlinerelocation.com",
                    "*.homeroom.school",
                    "*.leipzig-lamies.de",
                    "*.neeyemy.top",
                    "*.pizzeria-alfredo-oberhausen.de",
                    "*.publisher.school",
                    "*.serieamonamour.com",
                    "*.visitstlouis.com",
                    "40fy.io",
                    "anyhead.xyz",
                    "binaryedge.io",
                    "ccraftedstudio.tk",
                    "chiccomfort.ru",
                    "content.school",
                    "cozysleepoutdoor.com",
                    "fullstar.tk",
                    "greenlinerelocation.com",
                    "homeroom.school",
                    "leipzig-lamies.de",
                    "neeyemy.top",
                    "pizzeria-alfredo-oberhausen.de",
                    "publisher.school",
                    "serieamonamour.com",
                    "visitstlouis.com"
                  ]
                }
              },
              "serialNumber": "E660DA60E0E542B8D2239D07481507C9",
              "subject": {
                "commonName": "sni177528.cloudflaressl.com",
                "organizationalUnitName": "PositiveSSL Multi-Domain"
              },
              "subjectPublicKeyInfo": {
                "publicKeyAlgorithm": "id-ecPublicKey",
                "publicKeySize": "256 bit",
                "publicKey": {
                  "curve": "prime256v1",
                  "pub": "04:e5:8e:6b:70:34:fb:ec:1f:30:78:56:64:04:ca:37:ff:7d:12:fc:55:e5:93:f3:c9:85:4c:0e:e4:40:23:e4:6f:20:c0:a5:7b:a9:9d:92:ea:a5:d7:63:ae:13:74:bc:57:88:60:01:d2:96:6c:15:30:33:b3:b8:ae:af:f8:17:ef"
                }
              },
              "validity": {
                "notAfter": "Sep  3 23:59:59 2017 GMT",
                "notBefore": "Feb 23 00:00:00 2017 GMT"
              },
              "version": 2,
              "issuer": {
                "commonName": "COMODO ECC Domain Validation Secure Server CA 2",
                "localityName": "Salford",
                "organizationName": "COMODO CA Limited",
                "countryName": "GB",
                "stateOrProvinceName": "Greater Manchester"
              },
              "signatureAlgorithm": "ecdsa-with-SHA256",
              "signatureValue": "30:45:02:20:6d:ae:17:89:55:bd:04:9e:dc:50:85:0b:a3:a5:a3:dd:64:d9:e8:04:f4:e8:c4:bf:c5:80:6c:dd:a6:0a:55:e6:02:21:00:a5:62:13:ad:ce:59:51:6b:cb:d8:00:6a:6c:75:57:c3:5f:68:06:54:1f:eb:b0:57:8f:30:5d:e4:22:55:0f:56"
            },
            "sha1_fingerprint": "f1f4e08cda1c6d9e84d5f43b131e7e802cc498fb",
            "as_pem": "-----BEGIN CERTIFICATE-----\nMIIGPTCCBeOgAwIBAgIRAOZg2mDg5UK40iOdB0gVB8kwCgYIKoZIzj0EAwIwgZIx\nCzAJBgNVBAYTAkdCMRswGQYDVQQIExJHcmVhdGVyIE1hbmNoZXN0ZXIxEDAOBgNV\nBAcTB1NhbGZvcmQxGjAYBgNVBAoTEUNPTU9ETyBDQSBMaW1pdGVkMTgwNgYDVQQD\nEy9DT01PRE8gRUNDIERvbWFpbiBWYWxpZGF0aW9uIFNlY3VyZSBTZXJ2ZXIgQ0Eg\nMjAeFw0xNzAyMjMwMDAwMDBaFw0xNzA5MDMyMzU5NTlaMGwxITAfBgNVBAsTGERv\nbWFpbiBDb250cm9sIFZhbGlkYXRlZDEhMB8GA1UECxMYUG9zaXRpdmVTU0wgTXVs\ndGktRG9tYWluMSQwIgYDVQQDExtzbmkxNzc1MjguY2xvdWRmbGFyZXNzbC5jb20w\nWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATljmtwNPvsHzB4VmQEyjf/fRL8VeWT\n88mFTA7kQCPkbyDApXupnZLqpddjrhN0vFeIYAHSlmwVMDOzuK6v+Bfvo4IEPTCC\nBDkwHwYDVR0jBBgwFoAUQAlhZ/C8g3FP3hIILG/U1Ct2PZYwHQYDVR0OBBYEFCj7\nh56N9wvyrSx5t/g4dRML3grwMA4GA1UdDwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAA\nMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjBPBgNVHSAESDBGMDoGCysG\nAQQBsjEBAgIHMCswKQYIKwYBBQUHAgEWHWh0dHBzOi8vc2VjdXJlLmNvbW9kby5j\nb20vQ1BTMAgGBmeBDAECATBWBgNVHR8ETzBNMEugSaBHhkVodHRwOi8vY3JsLmNv\nbW9kb2NhNC5jb20vQ09NT0RPRUNDRG9tYWluVmFsaWRhdGlvblNlY3VyZVNlcnZl\nckNBMi5jcmwwgYgGCCsGAQUFBwEBBHwwejBRBggrBgEFBQcwAoZFaHR0cDovL2Ny\ndC5jb21vZG9jYTQuY29tL0NPTU9ET0VDQ0RvbWFpblZhbGlkYXRpb25TZWN1cmVT\nZXJ2ZXJDQTIuY3J0MCUGCCsGAQUFBzABhhlodHRwOi8vb2NzcC5jb21vZG9jYTQu\nY29tMIIChAYDVR0RBIICezCCAneCG3NuaTE3NzUyOC5jbG91ZGZsYXJlc3NsLmNv\nbYIJKi40MGZ5Lmlvgg0qLmFueWhlYWQueHl6gg8qLmJpbmFyeWVkZ2UuaW+CEyou\nY2NyYWZ0ZWRzdHVkaW8udGuCECouY2hpY2NvbWZvcnQucnWCECouY29udGVudC5z\nY2hvb2yCFiouY296eXNsZWVwb3V0ZG9vci5jb22CDSouZnVsbHN0YXIudGuCGSou\nZ3JlZW5saW5lcmVsb2NhdGlvbi5jb22CESouaG9tZXJvb20uc2Nob29sghMqLmxl\naXB6aWctbGFtaWVzLmRlgg0qLm5lZXllbXkudG9wgiAqLnBpenplcmlhLWFsZnJl\nZG8tb2JlcmhhdXNlbi5kZYISKi5wdWJsaXNoZXIuc2Nob29sghQqLnNlcmllYW1v\nbmFtb3VyLmNvbYISKi52aXNpdHN0bG91aXMuY29tggc0MGZ5LmlvggthbnloZWFk\nLnh5eoINYmluYXJ5ZWRnZS5pb4IRY2NyYWZ0ZWRzdHVkaW8udGuCDmNoaWNjb21m\nb3J0LnJ1gg5jb250ZW50LnNjaG9vbIIUY296eXNsZWVwb3V0ZG9vci5jb22CC2Z1\nbGxzdGFyLnRrghdncmVlbmxpbmVyZWxvY2F0aW9uLmNvbYIPaG9tZXJvb20uc2No\nb29sghFsZWlwemlnLWxhbWllcy5kZYILbmVleWVteS50b3CCHnBpenplcmlhLWFs\nZnJlZG8tb2JlcmhhdXNlbi5kZYIQcHVibGlzaGVyLnNjaG9vbIISc2VyaWVhbW9u\nYW1vdXIuY29tghB2aXNpdHN0bG91aXMuY29tMAoGCCqGSM49BAMCA0gAMEUCIG2u\nF4lVvQSe3FCFC6Olo91k2egE9OjEv8WAbN2mClXmAiEApWITrc5ZUWvL2ABqbHVX\nw19oBlQf67BXjzBd5CJVD1Y=\n-----END CERTIFICATE-----"
          },
          {
            "as_dict": {
              "extensions": {
                "X509v3 Authority Key Identifier": "keyid:75:71:A7:19:48:19:BC:9D:9D:EA:41:47:DF:94:C4:48:77:99:D3:79",
                "X509v3 Certificate Policies": {
                  "Policy": [
                    "X509v3 Any Policy",
                    "2.23.140.1.2.1"
                  ]
                },
                "Authority Information Access": {
                  "OCSP": {
                    "URI": [
                      "http://ocsp.comodoca4.com"
                    ]
                  },
                  "CAIssuers": {
                    "URI": [
                      "http://crt.comodoca.com/COMODOECCAddTrustCA.crt"
                    ]
                  }
                },
                "X509v3 Basic Constraints": {
                  "pathlen": [
                    "0"
                  ],
                  "CA": [
                    "TRUE"
                  ]
                },
                "X509v3 Key Usage": {
                  "CRL Sign": "",
                  "Digital Signature": "",
                  "Certificate Sign": ""
                },
                "X509v3 Extended Key Usage": {
                  "TLS Web Server Authentication": "",
                  "TLS Web Client Authentication": ""
                },
                "X509v3 Subject Key Identifier": "40:09:61:67:F0:BC:83:71:4F:DE:12:08:2C:6F:D4:D4:2B:76:3D:96",
                "X509v3 CRL Distribution Points": {
                  "Full Name": [
                    ""
                  ],
                  "URI": [
                    "http://crl.comodoca.com/COMODOECCCertificationAuthority.crl"
                  ]
                }
              },
              "serialNumber": "5B25CE6907C4265566D3390C99A954AD",
              "subject": {
                "commonName": "COMODO ECC Domain Validation Secure Server CA 2",
                "localityName": "Salford",
                "organizationName": "COMODO CA Limited",
                "countryName": "GB",
                "stateOrProvinceName": "Greater Manchester"
              },
              "subjectPublicKeyInfo": {
                "publicKeyAlgorithm": "id-ecPublicKey",
                "publicKeySize": "256 bit",
                "publicKey": {
                  "curve": "prime256v1",
                  "pub": "04:02:38:19:81:3a:c9:69:84:70:59:02:8e:a8:8a:1f:30:df:bc:de:03:fc:79:1d:3a:25:2c:6b:41:21:18:82:ea:f9:3e:4a:e4:33:cc:12:cf:2a:43:fc:0e:f2:64:00:c0:e1:25:50:82:24:cd:b6:49:38:0f:25:47:91:48:a4:ad"
                }
              },
              "validity": {
                "notAfter": "Sep 24 23:59:59 2029 GMT",
                "notBefore": "Sep 25 00:00:00 2014 GMT"
              },
              "version": 2,
              "issuer": {
                "commonName": "COMODO ECC Certification Authority",
                "localityName": "Salford",
                "organizationName": "COMODO CA Limited",
                "countryName": "GB",
                "stateOrProvinceName": "Greater Manchester"
              },
              "signatureAlgorithm": "ecdsa-with-SHA384",
              "signatureValue": "30:65:02:31:00:ac:68:47:25:80:13:4f:13:56:c0:a2:37:09:97:5a:50:c4:e7:ed:b4:61:cb:28:8a:0a:11:32:a6:e2:71:df:11:01:89:6f:07:7a:20:66:6b:18:d0:b9:2e:43:f7:52:6f:02:30:12:85:7c:8e:13:66:92:04:ba:9a:45:09:94:4a:30:61:d1:49:dc:6f:eb:e7:2d:c9:89:cf:1e:6a:7c:ec:85:ce:30:25:59:ba:81:70:34:b8:34:7f:e7:01:d1:e2:cb:52"
            },
            "sha1_fingerprint": "75cfd9bc5cefa104ecc1082d77e63392ccba5291",
            "as_pem": "-----BEGIN CERTIFICATE-----\nMIIDnzCCAyWgAwIBAgIQWyXOaQfEJlVm0zkMmalUrTAKBggqhkjOPQQDAzCBhTEL\nMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UE\nBxMHU2FsZm9yZDEaMBgGA1UEChMRQ09NT0RPIENBIExpbWl0ZWQxKzApBgNVBAMT\nIkNPTU9ETyBFQ0MgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMTQwOTI1MDAw\nMDAwWhcNMjkwOTI0MjM1OTU5WjCBkjELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdy\nZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UEBxMHU2FsZm9yZDEaMBgGA1UEChMRQ09N\nT0RPIENBIExpbWl0ZWQxODA2BgNVBAMTL0NPTU9ETyBFQ0MgRG9tYWluIFZhbGlk\nYXRpb24gU2VjdXJlIFNlcnZlciBDQSAyMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcD\nQgAEAjgZgTrJaYRwWQKOqIofMN+83gP8eR06JSxrQSEYgur5PkrkM8wSzypD/A7y\nZADA4SVQgiTNtkk4DyVHkUikraOCAWYwggFiMB8GA1UdIwQYMBaAFHVxpxlIGbyd\nnepBR9+UxEh3mdN5MB0GA1UdDgQWBBRACWFn8LyDcU/eEggsb9TUK3Y9ljAOBgNV\nHQ8BAf8EBAMCAYYwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHSUEFjAUBggrBgEF\nBQcDAQYIKwYBBQUHAwIwGwYDVR0gBBQwEjAGBgRVHSAAMAgGBmeBDAECATBMBgNV\nHR8ERTBDMEGgP6A9hjtodHRwOi8vY3JsLmNvbW9kb2NhLmNvbS9DT01PRE9FQ0ND\nZXJ0aWZpY2F0aW9uQXV0aG9yaXR5LmNybDByBggrBgEFBQcBAQRmMGQwOwYIKwYB\nBQUHMAKGL2h0dHA6Ly9jcnQuY29tb2RvY2EuY29tL0NPTU9ET0VDQ0FkZFRydXN0\nQ0EuY3J0MCUGCCsGAQUFBzABhhlodHRwOi8vb2NzcC5jb21vZG9jYTQuY29tMAoG\nCCqGSM49BAMDA2gAMGUCMQCsaEclgBNPE1bAojcJl1pQxOfttGHLKIoKETKm4nHf\nEQGJbwd6IGZrGNC5LkP3Um8CMBKFfI4TZpIEuppFCZRKMGHRSdxv6+ctyYnPHmp8\n7IXOMCVZuoFwNLg0f+cB0eLLUg==\n-----END CERTIFICATE-----"
          },
          {
            "as_dict": {
              "extensions": {
                "X509v3 Authority Key Identifier": "keyid:AD:BD:98:7A:34:B4:26:F7:FA:C4:26:54:EF:03:BD:E0:24:CB:54:1A",
                "X509v3 Certificate Policies": {
                  "Policy": [
                    "X509v3 Any Policy"
                  ]
                },
                "Authority Information Access": {
                  "OCSP": {
                    "URI": [
                      "http://ocsp.trust-provider.com"
                    ]
                  }
                },
                "X509v3 Basic Constraints": {
                  "CA": [
                    "TRUE"
                  ]
                },
                "X509v3 Key Usage": {
                  "CRL Sign": "",
                  "Digital Signature": "",
                  "Certificate Sign": ""
                },
                "X509v3 Subject Key Identifier": "75:71:A7:19:48:19:BC:9D:9D:EA:41:47:DF:94:C4:48:77:99:D3:79",
                "X509v3 CRL Distribution Points": {
                  "Full Name": [
                    ""
                  ],
                  "URI": [
                    "http://crl.trust-provider.com/AddTrustExternalCARoot.crl"
                  ]
                }
              },
              "serialNumber": "4352023FFAA8901F139FE3F4E5C1444E",
              "subject": {
                "commonName": "COMODO ECC Certification Authority",
                "localityName": "Salford",
                "organizationName": "COMODO CA Limited",
                "countryName": "GB",
                "stateOrProvinceName": "Greater Manchester"
              },
              "subjectPublicKeyInfo": {
                "publicKeyAlgorithm": "id-ecPublicKey",
                "publicKeySize": "384 bit",
                "publicKey": {
                  "curve": "secp384r1",
                  "pub": "04:03:47:7b:2f:75:c9:82:15:85:fb:75:e4:91:16:d4:ab:62:99:f5:3e:52:0b:06:ce:41:00:7f:97:e1:0a:24:3c:1d:01:04:ee:3d:d2:8d:09:97:0c:e0:75:e4:fa:fb:77:8a:2a:f5:03:60:4b:36:8b:16:23:16:ad:09:71:f4:4a:f4:28:50:b4:fe:88:1c:6e:3f:6c:2f:2f:09:59:5b:a5:5b:0b:33:99:e2:c3:3d:89:f9:6a:2c:ef:b2:d3:06:e9"
                }
              },
              "validity": {
                "notAfter": "May 30 10:48:38 2020 GMT",
                "notBefore": "May 30 10:48:38 2000 GMT"
              },
              "version": 2,
              "issuer": {
                "commonName": "AddTrust External CA Root",
                "organizationName": "AddTrust AB",
                "organizationalUnitName": "AddTrust External TTP Network",
                "countryName": "SE"
              },
              "signatureAlgorithm": "sha384WithRSAEncryption",
              "signatureValue": "1d:c7:fa:2e:40:b6:5c:05:4b:0f:bc:55:36:01:58:e0:53:05:3d:64:fb:ac:d9:a5:38:b8:a7:21:3b:af:95:5b:be:48:c8:d3:43:d4:21:6c:41:ed:09:2d:9c:73:00:71:9c:ae:21:73:7e:ff:8e:8d:b9:8e:58:90:8e:fc:8c:6d:76:c8:00:3a:9f:20:a6:2d:7d:cc:17:fd:cd:98:96:32:09:1a:c9:65:fc:04:eb:b4:9a:0a:78:e5:97:3b:52:8f:12:c2:74:97:01:9e:cf:e1:6d:68:d8:93:b9:9c:24:fb:96:27:48:01:9c:ea:94:3f:70:98:41:b3:73:51:37:29:e8:f6:01:7a:b9:27:b8:24:51:d9:11:68:d4:a6:85:a7:36:a7:a5:96:ba:80:f8:a6:fd:ae:6d:84:20:ae:35:76:73:42:0f:87:09:ec:c5:dc:e7:93:03:22:1a:97:ee:9a:8a:51:61:a7:97:26:1e:e9:ee:75:51:08:90:05:af:2f:9e:13:9c:93:3f:7a:ff:e6:eb:e9:68:79:8c:af:e0:b6:fa:ee:9b:12:13:fe:45:8c:d2:7c:d3:35:eb:21:12:93:fe:66:75:26:2a:15:84:26:f7:66:c9:cb:8d:bb:09:41:d4:18:af:b1:b3:10:f5:10:ca:9d:9a:0e:b5:75:6a:e8"
            },
            "sha1_fingerprint": "ae223cbf20191b40d7ffb4ea5701b65fdc68a1ca",
            "as_pem": "-----BEGIN CERTIFICATE-----\nMIID0DCCArigAwIBAgIQQ1ICP/qokB8Tn+P05cFETjANBgkqhkiG9w0BAQwFADBv\nMQswCQYDVQQGEwJTRTEUMBIGA1UEChMLQWRkVHJ1c3QgQUIxJjAkBgNVBAsTHUFk\nZFRydXN0IEV4dGVybmFsIFRUUCBOZXR3b3JrMSIwIAYDVQQDExlBZGRUcnVzdCBF\neHRlcm5hbCBDQSBSb290MB4XDTAwMDUzMDEwNDgzOFoXDTIwMDUzMDEwNDgzOFow\ngYUxCzAJBgNVBAYTAkdCMRswGQYDVQQIExJHcmVhdGVyIE1hbmNoZXN0ZXIxEDAO\nBgNVBAcTB1NhbGZvcmQxGjAYBgNVBAoTEUNPTU9ETyBDQSBMaW1pdGVkMSswKQYD\nVQQDEyJDT01PRE8gRUNDIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MHYwEAYHKoZI\nzj0CAQYFK4EEACIDYgAEA0d7L3XJghWF+3XkkRbUq2KZ9T5SCwbOQQB/l+EKJDwd\nAQTuPdKNCZcM4HXk+vt3iir1A2BLNosWIxatCXH0SvQoULT+iBxuP2wvLwlZW6Vb\nCzOZ4sM9iflqLO+y0wbpo4H+MIH7MB8GA1UdIwQYMBaAFK29mHo0tCb3+sQmVO8D\nveAky1QaMB0GA1UdDgQWBBR1cacZSBm8nZ3qQUfflMRId5nTeTAOBgNVHQ8BAf8E\nBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zARBgNVHSAECjAIMAYGBFUdIAAwSQYDVR0f\nBEIwQDA+oDygOoY4aHR0cDovL2NybC50cnVzdC1wcm92aWRlci5jb20vQWRkVHJ1\nc3RFeHRlcm5hbENBUm9vdC5jcmwwOgYIKwYBBQUHAQEELjAsMCoGCCsGAQUFBzAB\nhh5odHRwOi8vb2NzcC50cnVzdC1wcm92aWRlci5jb20wDQYJKoZIhvcNAQEMBQAD\nggEBAB3H+i5AtlwFSw+8VTYBWOBTBT1k+6zZpTi4pyE7r5VbvkjI00PUIWxB7Qkt\nnHMAcZyuIXN+/46NuY5YkI78jG12yAA6nyCmLX3MF/3NmJYyCRrJZfwE67SaCnjl\nlztSjxLCdJcBns/hbWjYk7mcJPuWJ0gBnOqUP3CYQbNzUTcp6PYBerknuCRR2RFo\n1KaFpzanpZa6gPim/a5thCCuNXZzQg+HCezF3OeTAyIal+6ailFhp5cmHunudVEI\nkAWvL54TnJM/ev/m6+loeYyv4Lb67psSE/5FjNJ80zXrIRKT/mZ1JioVhCb3ZsnL\njbsJQdQYr7GzEPUQyp2aDrV1aug=\n-----END CERTIFICATE-----"
          }
        ],
        "path_validation_result_list": [
          {
            "is_certificate_trusted": true,
            "trust_store": {
              "_certificate_list": null,
              "name": "Mozilla NSS",
              "version": "02/2016"
            },
            "verify_string": "ok"
          },
          {
            "is_certificate_trusted": true,
            "trust_store": {
              "_certificate_list": null,
              "name": "Microsoft",
              "version": "02/2016"
            },
            "verify_string": "ok"
          },
          {
            "is_certificate_trusted": true,
            "trust_store": {
              "_certificate_list": null,
              "name": "Apple",
              "version": "OS X 10.11.3"
            },
            "verify_string": "ok"
          },
          {
            "is_certificate_trusted": true,
            "trust_store": {
              "_certificate_list": null,
              "name": "Java 7",
              "version": "Update 79"
            },
            "verify_string": "ok"
          },
          {
            "is_certificate_trusted": true,
            "trust_store": {
              "_certificate_list": null,
              "name": "AOSP",
              "version": "N Preview 2"
            },
            "verify_string": "ok"
          }
        ]
      },
      "server_info": {
        "ssl_cipher_supported": "ECDHE-ECDSA-CHACHA20-POLY1305",
        "hostname": "binaryedge.io",
        "client_auth_requirement": 1,
        "highest_ssl_version_supported": 5,
        "port": 443,
        "http_tunneling_settings": null,
        "ip_address": "104.28.6.147",
        "client_auth_credentials": null,
        "tls_wrapped_protocol": 1,
        "xmpp_to_hostname": null,
        "tls_server_name_indication": "binaryedge.io"
      }
    }
  }
}
```
