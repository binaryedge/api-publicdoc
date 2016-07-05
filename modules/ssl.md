# SSL

## About

SSL Module can analyze the SSL configuration of a server by connecting to it.
It is designed to be fast and comprehensive and should help organizations and testers identify misconfigurations affecting their SSL servers.

#### Detailed Information:

 https://github.com/binaryedge/api-publicdoc/blob/master/modules/ssl-detailed.md

## Example:

### xxx.xxx.x.xxx:xxx


```json
{
    "origin": {
        "type": "ssl",
        "module": "grabber",
        "country": "fr",
        "ts": 1467734431877
    },
    "target": {
        "ip": "XXX.XXX.XXX.XXX",
        "port": 443
    },
    "result": {
        "data": {
            "certinfo_full": [{
                "certificateChain": [{
                    "certificate": [{
                        "asPEM": ["-----BEGIN CERTIFICATE-----\nMIICwjCCAaoCCQDQ8PV5AspYIzANBgkqhkiG9w0BAQsFADAjMQswCQYDVQQGEwJV\nUzEUMBIGA1UEAxMLMTkyLjE2OC4xLjEwHhcNMTYwNjEzMTAwNTM0WmouhcNMjYwNjE0\nMTAwNTM0WjAjMQswCQYDVQQGEwJVUzEUMBIGA1UEAxMLMTkyLjE2OC4xLjEwggEi\nMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCyx/ueg5ifraC6HDh8f9xru2BL\n9aKQz2vNJLIZgdSao+52q8T3JNqsUSju8Hd98clrsMFJXEQ/oOZP1CIFGE6zjK9H\nEeoAg0C3rSFcdmP65gljsugyM3uWnU55ZeGzEYyGPaAqGOTkWwOW2C146I+Vh3yZ\nyALLcIYNgnLWrCgzlqMfgt7eVc+0PVYQSs9KNibuWAnAVadD7OqtOk2zTqSjnbA1\nXJfu/5uEdQJ3twl7rXhgtpLcXux6a3ro/Ir+zaVzIZZ+/FYGCIv57fY+V4EpCudr\nPNmRfIzpnh5eNekfXC6q98lOn3Qhn7NC9zE07DkYco45ZLoivopq/DjPW8RjAgMB\nAAEwDQYJKoZIhvcNAQELBQADggEBADPa5iPSWRYhCv5PyElf+G7Ry0x1oqZOemmi\nu0UHsx/mPhdQOEswfHeMrTC0GYCI5sDgJEKkqK5a9dtzEEOwA/+3scBv7TXjVM+l\ndHpZ5+1AI9iidpSLBjpvirzMkT/aW850U9GIJn0aVGLOqfRYeulASIozJGYVvxYL\npr2oEj4YwD30J4PEPxEqLKP5cV8A55VdnEkJfkcddNOcAktwKE9/i3EbJTCmgOLy\nCWeBdrUiJMeZHNRjJ8tKTxcOsb2ssWWRxgv5JceQHDnxZoW6XFr7g5h5rA/6Gg9e\ndvchOIj+CqBdnFvrTtNbfl+ukXgHNCzydU6LPJ0dyFwFUlJe0vg=\n-----END CERTIFICATE-----"],
                        "issuer": [{
                            "countryName": ["US"],
                            "commonName": ["192.168.1.1"]
                        }],
                        "serialNumber": ["D0F0F57902CA5823"],
                        "subject": [{
                            "countryName": ["US"],
                            "commonName": ["192.168.1.1"]
                        }],
                        "validity": [{
                            "notBefore": ["Jun 13 10:05:34 2016 GMT"],
                            "notAfter": ["Jun 14 10:05:34 2026 GMT"]
                        }],
                        "subjectPublicKeyInfo": [{
                            "publicKey": [{
                                "modulus": ["00:b2:c7:fb:9e:83:98:9f:ad:a0:ba:1c:38:7c:7f:dc:6b:bb:60:4b:f5:a2:90:cf:6b:cd:24:b2:19:81:d4:9a:a3:ee:76:ab:c4:f7:24:da:ac:51:28:ee:f0:77:7d:f1:c9:6b:b0:c1:49:5c:44:3f:a0:e6:4f:d4:22:05:18:4e:b3:8c:af:47:11:ea:00:83:40:b7:ad:21:5c:76:63:fa:e6:09:63:b2:e8:32:33:7b:96:9d:4e:79:65:e1:b3:11:8c:86:3d:a0:2a:18:e4:e4:5b:03:96:d8:2d:78:e8:8f:95:87:7c:99:c8:02:cb:70:86:0d:82:72:d6:ac:28:33:96:a3:1f:82:de:de:55:cf:b4:3d:56:10:4a:cf:4a:36:26:ee:58:09:c0:55:a7:43:ec:ea:ad:3a:4d:b3:4e:a4:a3:9d:b0:35:5c:97:ee:ff:9b:84:75:02:77:b7:09:7b:ad:78:60:b6:92:dc:5e:ec:7a:6b:7a:e8:fc:8a:fe:cd:a5:73:21:96:7e:fc:56:06:08:8b:f9:ed:f6:3e:57:81:29:0a:e7:6b:3c:d9:91:7c:8c:e9:9e:1e:5e:35:e9:1f:5c:2e:aa:f7:c9:4e:9f:74:21:9f:b3:42:f7:31:34:ec:39:18:72:8e:39:64:ba:22:be:8a:6a:fc:38:cf:5b:c4:63"],
                                "exponent": ["65537"]
                            }],
                            "publicKeyAlgorithm": ["rsaEncryption"],
                            "publicKeySize": ["2048"]
                        }],
                        "version": ["0"],
                        "extensions": [""],
                        "signatureValue": ["33:da:e6:23:d2:59:16:21:0a:fe:4f:c8:49:5f:f8:6e:d1:cb:4c:75:a2:a6:4e:7a:69:a2:bb:45:07:b3:1f:e6:3e:17:50:38:4b:30:7c:77:8c:ad:30:b4:19:80:88:e6:c0:e0:24:42:a4:a8:ae:5a:f5:db:73:10:43:b0:03:ff:b7:b1:c0:6f:ed:35:e3:54:cf:a5:74:7a:59:e7:ed:40:23:d8:a2:76:94:8b:06:3a:6f:8a:bc:cc:91:3f:da:5b:ce:74:53:d1:88:26:7d:1a:54:62:ce:a9:f4:58:7a:e9:40:48:8a:33:24:66:15:bf:16:0b:a6:bd:a8:12:3e:18:c0:3d:f4:27:83:c4:3f:11:2a:2c:a3:f9:71:5f:00:e7:95:5d:9c:49:09:7e:47:1d:74:d3:9c:02:4b:70:28:4f:7f:8b:71:1b:25:30:a6:80:e2:f2:09:67:81:76:b5:22:24:c7:99:1c:d4:63:27:cb:4a:4f:17:0e:b1:bd:ac:b1:65:91:c6:0b:f9:25:c7:90:1c:39:f1:66:85:ba:5c:5a:fb:83:98:79:ac:0f:fa:1a:0f:5e:76:f7:21:38:88:fe:0a:a0:5d:9c:5b:eb:4e:d3:5b:7e:5f:ae:91:78:07:34:2c:f2:75:4e:8b:3c:9d:1d:c8:5c:05:52:52:5e:d2:f8"],
                        "signatureAlgorithm": ["sha256WithRSAEncryption"],
                        "position": "leaf",
                        "sha1Fingerprint": "27aacd98c957d9e42e03008ab79ad8b29599ab6e",
                        "suppliedServerNameIndication": "XXX.XXX.XXX.XXX"
                    }],
                    "hasSha1SignedCertificate": "False",
                    "isChainOrderValid": "True"
                }],
                "certificateValidation": [{
                    "hostnameValidation": [{
                        "certificateMatchesServerHostname": "False",
                        "serverHostname": "XXX.XXX.XXX.XXX"
                    }],
                    "pathValidation": [{
                        "trustStoreVersion": "02/2016",
                        "usingTrustStore": "Mozilla NSS",
                        "validationResult": "self signed certificate"
                    }, {
                        "trustStoreVersion": "02/2016",
                        "usingTrustStore": "Microsoft",
                        "validationResult": "self signed certificate"
                    }, {
                        "trustStoreVersion": "OS X 10.11.3",
                        "usingTrustStore": "Apple",
                        "validationResult": "self signed certificate"
                    }, {
                        "trustStoreVersion": "Update 65",
                        "usingTrustStore": "Java 6",
                        "validationResult": "self signed certificate"
                    }, {
                        "trustStoreVersion": "N Preview 2",
                        "usingTrustStore": "AOSP",
                        "validationResult": "self signed certificate"
                    }]
                }],
                "ocspStapling": [{
                    "isSupported": "False"
                }],
                "title": "Certificate Basic Information"
            }],
            "heartbleed": [{
                "exception": "timeout - timed out"
            }],
            "host": "XXX.XXX.XXX.XXX",
            "tlsWrappedProtocol": "plainTls"
        }
    }
}
```
