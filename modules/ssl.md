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
            "server_info": {...},
            "cert_info": {...},
            "ciphers": {...},
            "vulnerabilities": {...},
            "truststores": {...}
    }
}
```

### Contents of the fields:

  * **server_info** - Server Information.
  * **cert_info** - Certificates information.
  * **ciphers** - Tested ciphers and information about accepted, errored and preferred ciphers.
  * **vulnerabilities** - Vulnerabilities tests. Heartbleed and OpenSSL CCS.
  * **truststores** - Truststores validation of certificates.

## SSL Event Example

### Request

```
curl https://api.binaryedge.io/v1/tasks -d '{"type":"scan", "description": "SSL Request", "options":[{"targets":["X.X.X.X"], "ports":[{"port":"443", "protocol":"tcp", "modules": ["ssl"], "config":{"sni":"www.binaryedge.io", "ssl_mode":"full"}}]}]}' -H "X-Token:<Token>"
```

### Response

```json
{
  "origin": {
    "type": "ssl",
    "job_id": "tiago-715e6453-4dbc-49fb-afe4-1feb22bf64b2",
    "client_id": "tiago",
    "module": "grabber",
    "country": "uk",
    "ts": 1471951814799
  },
  "target": {
    "ip": "X.X.X.X",
    "port": 443
  },
  "result": {
    "data": {
      "server_info": {
        "client_auth_credentials": null,
        "client_auth_requirement": 1,
        "highest_ssl_version_supported": 5,
        "hostname": "X.X.X.X",
        "http_tunneling_settings": null,
        "ip_address": "X.X.X.X",
        "port": 443,
        "ssl_cipher_supported": "ECDHE-ECDSA-CHACHA20-POLY1305",
        "tls_server_name_indication": "www.binaryedge.io",
        "tls_wrapped_protocol": 1,
        "xmpp_to_hostname": null
      },
      "cert_info": {
        "certificate_chain": [
          {
            "as_dict": {
              "extensions": {
                "Authority Information Access": {
                  "CAIssuers": {
                    "URI": [
                      "http://crt.comodoca4.com/COMODOECCDomainValidationSecureServerCA2.crt"
                    ]
                  },
                  "OCSP": {
                    "URI": [
                      "http://ocsp.comodoca4.com"
                    ]
                  }
                },
                "X509v3 Authority Key Identifier": "keyid:40:09:61:67:F0:BC:83:71:4F:DE:12:08:2C:6F:D4:D4:2B:76:3D:96",
                "X509v3 Basic Constraints": {
                  "CA": [
                    "FALSE"
                  ]
                },
                "X509v3 CRL Distribution Points": {
                  "Full Name": [
                    ""
                  ],
                  "URI": [
                    "http://crl.comodoca4.com/COMODOECCDomainValidationSecureServerCA2.crl"
                  ]
                },
                "X509v3 Certificate Policies": {
                  "CPS": [
                    "https://secure.comodo.com/CPS"
                  ],
                  "Policy": [
                    "1.3.6.1.4.1.6449.1.2.2.7",
                    "2.23.140.1.2.1"
                  ]
                },
                "X509v3 Extended Key Usage": {
                  "TLS Web Client Authentication": "",
                  "TLS Web Server Authentication": ""
                },
                "X509v3 Key Usage": {
                  "Digital Signature": ""
                },
                "X509v3 Subject Alternative Name": {
                  "DNS": [
                    "sni177528.cloudflaressl.com",
                    "*.40fy.io",
                    "*.advrobotic62.gq",
                    "*.anyhead.xyz",
                    "*.binaryedge.io",
                    "*.bravoenjoyy7.cf",
                    "*.bravolinmr.cf",
                    "*.chiccomfort.ru",
                    "*.cozysleepoutdoor.com",
                    "*.filezonerite057.ga",
                    "*.greenlinerelocation.com",
                    "*.homeroom.school",
                    "*.leipzig-lamies.de",
                    "*.neeyemy.top",
                    "*.personalnocreditcheck.loan",
                    "*.pizzeria-alfredo-oberhausen.de",
                    "*.serieamonamour.com",
                    "*.wineinstalzonecnq.gq",
                    "*.zzfreeinstalzonen8.cf",
                    "40fy.io",
                    "advrobotic62.gq",
                    "anyhead.xyz",
                    "binaryedge.io",
                    "bravoenjoyy7.cf",
                    "bravolinmr.cf",
                    "chiccomfort.ru",
                    "cozysleepoutdoor.com",
                    "filezonerite057.ga",
                    "greenlinerelocation.com",
                    "homeroom.school",
                    "leipzig-lamies.de",
                    "neeyemy.top",
                    "personalnocreditcheck.loan",
                    "pizzeria-alfredo-oberhausen.de",
                    "serieamonamour.com",
                    "wineinstalzonecnq.gq",
                    "zzfreeinstalzonen8.cf"
                  ]
                },
                "X509v3 Subject Key Identifier": "28:FB:87:9E:8D:F7:0B:F2:AD:2C:79:B7:F8:38:75:13:0B:DE:0A:F0"
              },
              "issuer": {
                "commonName": "COMODO ECC Domain Validation Secure Server CA 2",
                "countryName": "GB",
                "localityName": "Salford",
                "organizationName": "COMODO CA Limited",
                "stateOrProvinceName": "Greater Manchester"
              },
              "serialNumber": "E020DABB9BF82B7B161D7B217F4CFD9D",
              "signatureAlgorithm": "ecdsa-with-SHA256",
              "signatureValue": "30:45:02:21:00:93:f9:83:68:a4:ce:9f:94:80:d1:ba:c2:b6:55:c2:65:60:9a:f0:55:28:fe:82:dc:17:df:05:95:b1:a5:de:37:02:20:61:61:42:d3:33:10:d1:d4:c3:8c:78:8e:a2:d5:0b:26:39:f9:1a:38:67:9d:50:0f:5a:33:cd:96:54:af:c9:e6",
              "subject": {
                "commonName": "sni177528.cloudflaressl.com",
                "organizationalUnitName": "PositiveSSL Multi-Domain"
              },
              "subjectPublicKeyInfo": {
                "publicKey": {
                  "curve": "prime256v1",
                  "pub": "04:e5:8e:6b:70:34:fb:ec:1f:30:78:56:64:04:ca:37:ff:7d:12:fc:55:e5:93:f3:c9:85:4c:0e:e4:40:23:e4:6f:20:c0:a5:7b:a9:9d:92:ea:a5:d7:63:ae:13:74:bc:57:88:60:01:d2:96:6c:15:30:33:b3:b8:ae:af:f8:17:ef"
                },
                "publicKeyAlgorithm": "id-ecPublicKey",
                "publicKeySize": "256 bit"
              },
              "validity": {
                "notAfter": "Feb 12 23:59:59 2017 GMT",
                "notBefore": "Aug  9 00:00:00 2016 GMT"
              },
              "version": 2
            },
            "as_pem": "-----BEGIN CERTIFICATE-----\nMIIGtTCCBlugAwIBAgIRAOAg2rub+Ct7Fh17IX9M/Z0wCgYIKoZIzj0EAwIwgZIx\nCzAJBgNVBAYTAkdCMRswGQYDVQQIExJHcmVhdGVyIE1hbmNoZXN0ZXIxEDAOBgNV\nBAcTB1NhbGZvcmQxGjAYBgNVBAoTEUNPTU9ETyBDQSBMaW1pdGVkMTgwNgYDVQQD\nEy9DT01PRE8gRUNDIERvbWFpbiBWYWxpZGF0aW9uIFNlY3VyZSBTZXJ2ZXIgQ0Eg\nMjAeFw0xNjA4MDkwMDAwMDBaFw0xNzAyMTIyMzU5NTlaMGwxITAfBgNVBAsTGERv\nbWFpbiBDb250cm9sIFZhbGlkYXRlZDEhMB8GA1UECxMYUG9zaXRpdmVTU0wgTXVs\ndGktRG9tYWluMSQwIgYDVQQDExtzbmkxNzc1MjguY2xvdWRmbGFyZXNzbC5jb20w\nWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATljmtwNPvsHzB4VmQEyjf/fRL8VeWT\n88mFTA7kQCPkbyDApXupnZLqpddjrhN0vFeIYAHSlmwVMDOzuK6v+Bfvo4IEtTCC\nBLEwHwYDVR0jBBgwFoAUQAlhZ/C8g3FP3hIILG/U1Ct2PZYwHQYDVR0OBBYEFCj7\nh56N9wvyrSx5t/g4dRML3grwMA4GA1UdDwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAA\nMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjBPBgNVHSAESDBGMDoGCysG\nAQQBsjEBAgIHMCswKQYIKwYBBQUHAgEWHWh0dHBzOi8vc2VjdXJlLmNvbW9kby5j\nb20vQ1BTMAgGBmeBDAECATBWBgNVHR8ETzBNMEugSaBHhkVodHRwOi8vY3JsLmNv\nbW9kb2NhNC5jb20vQ09NT0RPRUNDRG9tYWluVmFsaWRhdGlvblNlY3VyZVNlcnZl\nckNBMi5jcmwwgYgGCCsGAQUFBwEBBHwwejBRBggrBgEFBQcwAoZFaHR0cDovL2Ny\ndC5jb21vZG9jYTQuY29tL0NPTU9ET0VDQ0RvbWFpblZhbGlkYXRpb25TZWN1cmVT\nZXJ2ZXJDQTIuY3J0MCUGCCsGAQUFBzABhhlodHRwOi8vb2NzcC5jb21vZG9jYTQu\nY29tMIIC/AYDVR0RBIIC8zCCAu+CG3NuaTE3NzUyOC5jbG91ZGZsYXJlc3NsLmNv\nbYIJKi40MGZ5LmlvghEqLmFkdnJvYm90aWM2Mi5ncYINKi5hbnloZWFkLnh5eoIP\nKi5iaW5hcnllZGdlLmlvghEqLmJyYXZvZW5qb3l5Ny5jZoIPKi5icmF2b2xpbm1y\nLmNmghAqLmNoaWNjb21mb3J0LnJ1ghYqLmNvenlzbGVlcG91dGRvb3IuY29tghQq\nLmZpbGV6b25lcml0ZTA1Ny5nYYIZKi5ncmVlbmxpbmVyZWxvY2F0aW9uLmNvbYIR\nKi5ob21lcm9vbS5zY2hvb2yCEyoubGVpcHppZy1sYW1pZXMuZGWCDSoubmVleWVt\neS50b3CCHCoucGVyc29uYWxub2NyZWRpdGNoZWNrLmxvYW6CICoucGl6emVyaWEt\nYWxmcmVkby1vYmVyaGF1c2VuLmRlghQqLnNlcmllYW1vbmFtb3VyLmNvbYIWKi53\naW5laW5zdGFsem9uZWNucS5ncYIXKi56emZyZWVpbnN0YWx6b25lbjguY2aCBzQw\nZnkuaW+CD2FkdnJvYm90aWM2Mi5ncYILYW55aGVhZC54eXqCDWJpbmFyeWVkZ2Uu\naW+CD2JyYXZvZW5qb3l5Ny5jZoINYnJhdm9saW5tci5jZoIOY2hpY2NvbWZvcnQu\ncnWCFGNvenlzbGVlcG91dGRvb3IuY29tghJmaWxlem9uZXJpdGUwNTcuZ2GCF2dy\nZWVubGluZXJlbG9jYXRpb24uY29tgg9ob21lcm9vbS5zY2hvb2yCEWxlaXB6aWct\nbGFtaWVzLmRlggtuZWV5ZW15LnRvcIIacGVyc29uYWxub2NyZWRpdGNoZWNrLmxv\nYW6CHnBpenplcmlhLWFsZnJlZG8tb2JlcmhhdXNlbi5kZYISc2VyaWVhbW9uYW1v\ndXIuY29tghR3aW5laW5zdGFsem9uZWNucS5ncYIVenpmcmVlaW5zdGFsem9uZW44\nLmNmMAoGCCqGSM49BAMCA0gAMEUCIQCT+YNopM6flIDRusK2VcJlYJrwVSj+gtwX\n3wWVsaXeNwIgYWFC0zMQ0dTDjHiOotULJjn5GjhnnVAPWjPNllSvyeY=\n-----END CERTIFICATE-----",
            "sha1_fingerprint": "a41b78af6e1e666b74baecd4ae922b429fcda587"
          },
          {
            "as_dict": {
              "extensions": {
                "Authority Information Access": {
                  "CAIssuers": {
                    "URI": [
                      "http://crt.comodoca.com/COMODOECCAddTrustCA.crt"
                    ]
                  },
                  "OCSP": {
                    "URI": [
                      "http://ocsp.comodoca4.com"
                    ]
                  }
                },
                "X509v3 Authority Key Identifier": "keyid:75:71:A7:19:48:19:BC:9D:9D:EA:41:47:DF:94:C4:48:77:99:D3:79",
                "X509v3 Basic Constraints": {
                  "CA": [
                    "TRUE"
                  ],
                  "pathlen": [
                    "0"
                  ]
                },
                "X509v3 CRL Distribution Points": {
                  "Full Name": [
                    ""
                  ],
                  "URI": [
                    "http://crl.comodoca.com/COMODOECCCertificationAuthority.crl"
                  ]
                },
                "X509v3 Certificate Policies": {
                  "Policy": [
                    "X509v3 Any Policy",
                    "2.23.140.1.2.1"
                  ]
                },
                "X509v3 Extended Key Usage": {
                  "TLS Web Client Authentication": "",
                  "TLS Web Server Authentication": ""
                },
                "X509v3 Key Usage": {
                  "CRL Sign": "",
                  "Certificate Sign": "",
                  "Digital Signature": ""
                },
                "X509v3 Subject Key Identifier": "40:09:61:67:F0:BC:83:71:4F:DE:12:08:2C:6F:D4:D4:2B:76:3D:96"
              },
              "issuer": {
                "commonName": "COMODO ECC Certification Authority",
                "countryName": "GB",
                "localityName": "Salford",
                "organizationName": "COMODO CA Limited",
                "stateOrProvinceName": "Greater Manchester"
              },
              "serialNumber": "5B25CE6907C4265566D3390C99A954AD",
              "signatureAlgorithm": "ecdsa-with-SHA384",
              "signatureValue": "30:65:02:31:00:ac:68:47:25:80:13:4f:13:56:c0:a2:37:09:97:5a:50:c4:e7:ed:b4:61:cb:28:8a:0a:11:32:a6:e2:71:df:11:01:89:6f:07:7a:20:66:6b:18:d0:b9:2e:43:f7:52:6f:02:30:12:85:7c:8e:13:66:92:04:ba:9a:45:09:94:4a:30:61:d1:49:dc:6f:eb:e7:2d:c9:89:cf:1e:6a:7c:ec:85:ce:30:25:59:ba:81:70:34:b8:34:7f:e7:01:d1:e2:cb:52",
              "subject": {
                "commonName": "COMODO ECC Domain Validation Secure Server CA 2",
                "countryName": "GB",
                "localityName": "Salford",
                "organizationName": "COMODO CA Limited",
                "stateOrProvinceName": "Greater Manchester"
              },
              "subjectPublicKeyInfo": {
                "publicKey": {
                  "curve": "prime256v1",
                  "pub": "04:02:38:19:81:3a:c9:69:84:70:59:02:8e:a8:8a:1f:30:df:bc:de:03:fc:79:1d:3a:25:2c:6b:41:21:18:82:ea:f9:3e:4a:e4:33:cc:12:cf:2a:43:fc:0e:f2:64:00:c0:e1:25:50:82:24:cd:b6:49:38:0f:25:47:91:48:a4:ad"
                },
                "publicKeyAlgorithm": "id-ecPublicKey",
                "publicKeySize": "256 bit"
              },
              "validity": {
                "notAfter": "Sep 24 23:59:59 2029 GMT",
                "notBefore": "Sep 25 00:00:00 2014 GMT"
              },
              "version": 2
            },
            "as_pem": "-----BEGIN CERTIFICATE-----\nMIIDnzCCAyWgAwIBAgIQWyXOaQfEJlVm0zkMmalUrTAKBggqhkjOPQQDAzCBhTEL\nMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UE\nBxMHU2FsZm9yZDEaMBgGA1UEChMRQ09NT0RPIENBIExpbWl0ZWQxKzApBgNVBAMT\nIkNPTU9ETyBFQ0MgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMTQwOTI1MDAw\nMDAwWhcNMjkwOTI0MjM1OTU5WjCBkjELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdy\nZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UEBxMHU2FsZm9yZDEaMBgGA1UEChMRQ09N\nT0RPIENBIExpbWl0ZWQxODA2BgNVBAMTL0NPTU9ETyBFQ0MgRG9tYWluIFZhbGlk\nYXRpb24gU2VjdXJlIFNlcnZlciBDQSAyMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcD\nQgAEAjgZgTrJaYRwWQKOqIofMN+83gP8eR06JSxrQSEYgur5PkrkM8wSzypD/A7y\nZADA4SVQgiTNtkk4DyVHkUikraOCAWYwggFiMB8GA1UdIwQYMBaAFHVxpxlIGbyd\nnepBR9+UxEh3mdN5MB0GA1UdDgQWBBRACWFn8LyDcU/eEggsb9TUK3Y9ljAOBgNV\nHQ8BAf8EBAMCAYYwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHSUEFjAUBggrBgEF\nBQcDAQYIKwYBBQUHAwIwGwYDVR0gBBQwEjAGBgRVHSAAMAgGBmeBDAECATBMBgNV\nHR8ERTBDMEGgP6A9hjtodHRwOi8vY3JsLmNvbW9kb2NhLmNvbS9DT01PRE9FQ0ND\nZXJ0aWZpY2F0aW9uQXV0aG9yaXR5LmNybDByBggrBgEFBQcBAQRmMGQwOwYIKwYB\nBQUHMAKGL2h0dHA6Ly9jcnQuY29tb2RvY2EuY29tL0NPTU9ET0VDQ0FkZFRydXN0\nQ0EuY3J0MCUGCCsGAQUFBzABhhlodHRwOi8vb2NzcC5jb21vZG9jYTQuY29tMAoG\nCCqGSM49BAMDA2gAMGUCMQCsaEclgBNPE1bAojcJl1pQxOfttGHLKIoKETKm4nHf\nEQGJbwd6IGZrGNC5LkP3Um8CMBKFfI4TZpIEuppFCZRKMGHRSdxv6+ctyYnPHmp8\n7IXOMCVZuoFwNLg0f+cB0eLLUg==\n-----END CERTIFICATE-----",
            "sha1_fingerprint": "75cfd9bc5cefa104ecc1082d77e63392ccba5291"
          },
          {
            "as_dict": {
              "extensions": {
                "Authority Information Access": {
                  "OCSP": {
                    "URI": [
                      "http://ocsp.trust-provider.com"
                    ]
                  }
                },
                "X509v3 Authority Key Identifier": "keyid:AD:BD:98:7A:34:B4:26:F7:FA:C4:26:54:EF:03:BD:E0:24:CB:54:1A",
                "X509v3 Basic Constraints": {
                  "CA": [
                    "TRUE"
                  ]
                },
                "X509v3 CRL Distribution Points": {
                  "Full Name": [
                    ""
                  ],
                  "URI": [
                    "http://crl.trust-provider.com/AddTrustExternalCARoot.crl"
                  ]
                },
                "X509v3 Certificate Policies": {
                  "Policy": [
                    "X509v3 Any Policy"
                  ]
                },
                "X509v3 Key Usage": {
                  "CRL Sign": "",
                  "Certificate Sign": "",
                  "Digital Signature": ""
                },
                "X509v3 Subject Key Identifier": "75:71:A7:19:48:19:BC:9D:9D:EA:41:47:DF:94:C4:48:77:99:D3:79"
              },
              "issuer": {
                "commonName": "AddTrust External CA Root",
                "countryName": "SE",
                "organizationName": "AddTrust AB",
                "organizationalUnitName": "AddTrust External TTP Network"
              },
              "serialNumber": "4352023FFAA8901F139FE3F4E5C1444E",
              "signatureAlgorithm": "sha384WithRSAEncryption",
              "signatureValue": "1d:c7:fa:2e:40:b6:5c:05:4b:0f:bc:55:36:01:58:e0:53:05:3d:64:fb:ac:d9:a5:38:b8:a7:21:3b:af:95:5b:be:48:c8:d3:43:d4:21:6c:41:ed:09:2d:9c:73:00:71:9c:ae:21:73:7e:ff:8e:8d:b9:8e:58:90:8e:fc:8c:6d:76:c8:00:3a:9f:20:a6:2d:7d:cc:17:fd:cd:98:96:32:09:1a:c9:65:fc:04:eb:b4:9a:0a:78:e5:97:3b:52:8f:12:c2:74:97:01:9e:cf:e1:6d:68:d8:93:b9:9c:24:fb:96:27:48:01:9c:ea:94:3f:70:98:41:b3:73:51:37:29:e8:f6:01:7a:b9:27:b8:24:51:d9:11:68:d4:a6:85:a7:36:a7:a5:96:ba:80:f8:a6:fd:ae:6d:84:20:ae:35:76:73:42:0f:87:09:ec:c5:dc:e7:93:03:22:1a:97:ee:9a:8a:51:61:a7:97:26:1e:e9:ee:75:51:08:90:05:af:2f:9e:13:9c:93:3f:7a:ff:e6:eb:e9:68:79:8c:af:e0:b6:fa:ee:9b:12:13:fe:45:8c:d2:7c:d3:35:eb:21:12:93:fe:66:75:26:2a:15:84:26:f7:66:c9:cb:8d:bb:09:41:d4:18:af:b1:b3:10:f5:10:ca:9d:9a:0e:b5:75:6a:e8",
              "subject": {
                "commonName": "COMODO ECC Certification Authority",
                "countryName": "GB",
                "localityName": "Salford",
                "organizationName": "COMODO CA Limited",
                "stateOrProvinceName": "Greater Manchester"
              },
              "subjectPublicKeyInfo": {
                "publicKey": {
                  "curve": "secp384r1",
                  "pub": "04:03:47:7b:2f:75:c9:82:15:85:fb:75:e4:91:16:d4:ab:62:99:f5:3e:52:0b:06:ce:41:00:7f:97:e1:0a:24:3c:1d:01:04:ee:3d:d2:8d:09:97:0c:e0:75:e4:fa:fb:77:8a:2a:f5:03:60:4b:36:8b:16:23:16:ad:09:71:f4:4a:f4:28:50:b4:fe:88:1c:6e:3f:6c:2f:2f:09:59:5b:a5:5b:0b:33:99:e2:c3:3d:89:f9:6a:2c:ef:b2:d3:06:e9"
                },
                "publicKeyAlgorithm": "id-ecPublicKey",
                "publicKeySize": "384 bit"
              },
              "validity": {
                "notAfter": "May 30 10:48:38 2020 GMT",
                "notBefore": "May 30 10:48:38 2000 GMT"
              },
              "version": 2
            },
            "as_pem": "-----BEGIN CERTIFICATE-----\nMIID0DCCArigAwIBAgIQQ1ICP/qokB8Tn+P05cFETjANBgkqhkiG9w0BAQwFADBv\nMQswCQYDVQQGEwJTRTEUMBIGA1UEChMLQWRkVHJ1c3QgQUIxJjAkBgNVBAsTHUFk\nZFRydXN0IEV4dGVybmFsIFRUUCBOZXR3b3JrMSIwIAYDVQQDExlBZGRUcnVzdCBF\neHRlcm5hbCBDQSBSb290MB4XDTAwMDUzMDEwNDgzOFoXDTIwMDUzMDEwNDgzOFow\ngYUxCzAJBgNVBAYTAkdCMRswGQYDVQQIExJHcmVhdGVyIE1hbmNoZXN0ZXIxEDAO\nBgNVBAcTB1NhbGZvcmQxGjAYBgNVBAoTEUNPTU9ETyBDQSBMaW1pdGVkMSswKQYD\nVQQDEyJDT01PRE8gRUNDIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MHYwEAYHKoZI\nzj0CAQYFK4EEACIDYgAEA0d7L3XJghWF+3XkkRbUq2KZ9T5SCwbOQQB/l+EKJDwd\nAQTuPdKNCZcM4HXk+vt3iir1A2BLNosWIxatCXH0SvQoULT+iBxuP2wvLwlZW6Vb\nCzOZ4sM9iflqLO+y0wbpo4H+MIH7MB8GA1UdIwQYMBaAFK29mHo0tCb3+sQmVO8D\nveAky1QaMB0GA1UdDgQWBBR1cacZSBm8nZ3qQUfflMRId5nTeTAOBgNVHQ8BAf8E\nBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zARBgNVHSAECjAIMAYGBFUdIAAwSQYDVR0f\nBEIwQDA+oDygOoY4aHR0cDovL2NybC50cnVzdC1wcm92aWRlci5jb20vQWRkVHJ1\nc3RFeHRlcm5hbENBUm9vdC5jcmwwOgYIKwYBBQUHAQEELjAsMCoGCCsGAQUFBzAB\nhh5odHRwOi8vb2NzcC50cnVzdC1wcm92aWRlci5jb20wDQYJKoZIhvcNAQEMBQAD\nggEBAB3H+i5AtlwFSw+8VTYBWOBTBT1k+6zZpTi4pyE7r5VbvkjI00PUIWxB7Qkt\nnHMAcZyuIXN+/46NuY5YkI78jG12yAA6nyCmLX3MF/3NmJYyCRrJZfwE67SaCnjl\nlztSjxLCdJcBns/hbWjYk7mcJPuWJ0gBnOqUP3CYQbNzUTcp6PYBerknuCRR2RFo\n1KaFpzanpZa6gPim/a5thCCuNXZzQg+HCezF3OeTAyIal+6ailFhp5cmHunudVEI\nkAWvL54TnJM/ev/m6+loeYyv4Lb67psSE/5FjNJ80zXrIRKT/mZ1JioVhCb3ZsnL\njbsJQdQYr7GzEPUQyp2aDrV1aug=\n-----END CERTIFICATE-----",
            "sha1_fingerprint": "ae223cbf20191b40d7ffb4ea5701b65fdc68a1ca"
          }
        ],
        "hostname_validation_result": 1,
        "is_certificate_chain_order_valid": true,
        "is_leaf_certificate_ev": false,
        "is_ocsp_response_trusted": true,
        "ocsp_response": {
          "producedAt": "Aug 21 16:19:40 2016 GMT",
          "responderID": "40096167F0BC83714FDE12082C6FD4D42B763D96",
          "responseStatus": "successful",
          "responseType": "Basic OCSP Response",
          "responses": [
            {
              "certID": {
                "hashAlgorithm": "sha1",
                "issuerKeyHash": "40096167F0BC83714FDE12082C6FD4D42B763D96",
                "issuerNameHash": "CEA633847FA2C6D73E768EA031C03953C6868E0A",
                "serialNumber": "E020DABB9BF82B7B161D7B217F4CFD9D"
              },
              "certStatus": "good",
              "nextUpdate": "Aug 25 16:19:40 2016 GMT",
              "thisUpdate": "Aug 21 16:19:40 2016 GMT"
            }
          ],
          "version": "1"
        },
        "path_validation_result_list": [
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
              "name": "Mozilla NSS",
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
      "vulnerabilities": {
        "heartbleed": {
          "is_vulnerable_to_heartbleed": false
        },
        "openssl_ccs": {
          "is_vulnerable_to_ccs_injection": false
        }
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
              "name": "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
              "post_handshake_response": ""
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
              "name": "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
              "post_handshake_response": ""
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
              "key_size": 112,
              "name": "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
              "post_handshake_response": ""
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
            "name": "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
            "post_handshake_response": ""
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
              "name": "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
              "post_handshake_response": ""
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
              "name": "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
              "post_handshake_response": ""
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
              "key_size": 112,
              "name": "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
              "post_handshake_response": ""
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
            "name": "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
            "post_handshake_response": ""
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
              "name": "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
              "post_handshake_response": ""
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
              "name": "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
              "post_handshake_response": ""
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
              "name": "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
              "post_handshake_response": ""
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
              "name": "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
              "post_handshake_response": ""
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
              "name": "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
              "post_handshake_response": ""
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
              "name": "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
              "post_handshake_response": ""
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
              "name": "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
              "post_handshake_response": ""
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
              "key_size": 112,
              "name": "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
              "post_handshake_response": ""
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
            "key_size": 256,
            "name": "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
            "post_handshake_response": ""
          }
        }
      },
      "truststores": [
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
            "name": "Mozilla NSS",
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
    }
  }
}
```
