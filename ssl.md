### About
SSL Module can analyze the SSL configuration of a server by connecting to it. 
It is designed to be fast and comprehensive and should help organizations and testers identify misconfigurations affecting their SSL servers.


# How to read the list:


###Dictionaries:

```
data: 
```
	
> when you have "name: \<empty\>" means that inside **json[data]** you have a **dictionary**   
> *example*: json["a"] -> Dict { b: 'bb', c: 'cc' }  
> *example*: json["a"]["b"] -> bb


###Arrays:

```python  
certinfo: [list]
[int]:

```

> when you have "name: [list]" means that returns an **array**.  
> *example*: json["certinfo"] -> Array [a,b,c,d]  
> *example*: json["certinfo"][0] -> a  
> *example*: json["certinfo"].length -> 1


###Strings:

```
ip: string
```
	
> when you have "name: string" means that returns a **string**.  
> *example*: json["ip"] -> "xxx.x.x.x"


###Boolean's:

```python  
anonymous: True/False
```

> when you have "name: True/False" means that returns a **boolean**.  
> *example*: json["anonymous"] -> True


###Optionals:

```python
acceptedCipherSuites: [list]
[int]:
	["" OR cipherSuite] [list]
	[int]:
		[keyExchange]: [list]
```

> when you have **"[ ]"** like **"[name]"** that means its optional, may have or not depends on the scan and data collected.   
> So in the **"[keyExchange]"** you can see that is an **Array** but is optinal, so you may have  **"keyExchange"** or **not**.   
> 
> But **"acceptedCipherSuites"** is different, it can return the key **"cipherSuite"** _*OR*_ it will return a string **""**, depending on the data.  
> *example*: json["scan1"]["acceptedCipherSuites"][0] -> { cipherSuite: ... }  
> *example*: json["scan2"]["acceptedCipherSuites"][0] -> ""  
  
> when you see a **"[int]:"** think of an index/position inside an array, again, depends on the data. 
> *example*: "test[int]:" test[0] ok, test[1] ok, test[2] error  


###Errors:

> `[exception]: string`  
> **Note**: the name "exception" is when the scan got an error on that plugin, keep that in mind.


---

# Json Output List:
### Standart 443 SSL Scan

```python

[ip]: string #ex: xx.xxx.xxx.xx

[ipv6]: string #ex: xxxx:xxxx:xxxx:xxx::xx

port: string #ex: 443

[host]: string #ex: firefox.com

data:
	
	#Test the validity of the certificates and get relevant information from the certificate. 
	certinfo: [list] 
	[int]:
		certificateChain: [list]
		[int]:
			certificate: [list]
			[int]:
				asPEM: [list]
				[int]: string #ex:[0] Return the certificate 

				subjectPublicKeyinfo: [list]
				[int]: 
					publicKey: [list]
					[int]:
						modulus: [list]
						[int]: string #ex:[0] xxxx:xxxx:xxxx:xxx::xx

						exponent: [list]
						[int]: string #ex:[0] 65537

					publicKeyAlgorithm: [list]
					[int]: string #ex:[0] rsaEncryption

					publicKeySize: [list]
					[int]: string #ex:[0] 2048

				version: [list] 
				[int]: string #ex:[0] 2

				extensions: [list]
				[int]:
					X509v3SubjectKeyIdentifier: [list]
					[int]: string #ex:[0] 6A:B1:53:FF:24:2D:F4:1E:D6:E2:F1:D5:5F:8D:BE:FB:44:76:35:18
					
					X509v3ExtendedKeyUsage: [list]
					[int]:
						
						TLSWebClientAuthentication: [list]
						[int]: string
						
						TLSWebServerAuthentication: [list]
						[int]: string
						
						AuthorityInformationAccess: [list]
						[int]:
							CAIssuers: [list]
							[int]:
								URI: [list]
								[int]:
									listEntry: [list]
									[int]: string #ex:[0] http://cacerts.digicert.com/DigiCertSHA2SecureServerCA.crt
							OCSP: [list]
							[int]:
								URI: [list]
								[int]:
									listEntry: [list]
									[int]: string #ex:[0] http://ocsp.digicert.com				
						
						X509v3CRLDistributionPoints: [list]
						[int]:
							FullName: [list]
							[int]:
								listEntry: [list]
								[int]: string
							URI: [list]
							[int]:
								listEntry: [list]
								[int]: string 
								#ex:[0] http://crl3.digicert.com/ssca-sha2-g4.crl
								#ex:[1] http://crl4.digicert.com/ssca-sha2-g4.crl  
						
						X509v3BasicConstraints: [list]
						[int]: string #ex:[0] CA:FALSE

						X509v3KeyUsage: [list]
						[int]:
							CRLSign: [list]
							[int]: string
							KeyEncipherment: [list]
							[int]: string
							DigitalSignature: [list]
							[int]: string

						X509v3SubjectAlternativeName: [list]
						[int]: [list]
							DNS: [list]
							[int]:
								listEntry: [list]
								[int]: string
								#ex:[0] static-san.mozilla.org
								#ex:[1] addons.mozilla.com
								#ex:[2] autoconfig-live.mozillamessaging.com
								#...

						X509v3AuthorityKeyIdentifier: [list]
						[int]: string #ex:[0] keyid:0F:80:61:1C:82:31:61:D5:2F:28:E7:8D:46:38:B4:2C:E1:C6:D9:E2
						
						X509v3CertificatePolicies: [list]
						[int]: [list]
							Policy: [list]
							[int]:
								listEntry: [list]
								[int]: string #ex:[0] 2.16.840.1.114412.1.1

							CPS: [list]
							[int]:
								listEntry: [list]
								[int]: string #ex:[0] https://www.digicert.com/CPS

				signatureValue: [list]
				[int]: string #ex:[0] 4b:a4:db:df:3c:83:e5:34:34:d9:18:ff:15:f1:e4:5a:c3...

				signatureAlgorithm: [list]
				[int]: string #ex:[0] sha256WithRSAEncryption

				serialnumber: [list]
				[int]: value #ex: 0273213B48220C3CE06B4560AF04455B

				subject: [list]
				[int]: 
						countryName: [list]
						[int]: string #ex:[0] US

						commonName: [list]
						[int]: string #ex:[0] static-san.mozilla.org

						organizationName: [list]
						[int]: string #ex:[0] Mozilla Foundation

						localityName: [list]
						[int]: string #ex:[0] Mountain View

						stateOrProvinceName: [list]
						[int]: string #ex:[0] California

				validity: [list]
				[int]:
					notAfter: [list]
					[int]: string #ex:[0] Nov 22 12:00:00 2016 GMT
					
					notBefore: [list]
					[int]: string #ex:[0] Feb  6 00:00:00 2014 GMT

				issuer: [list]
				[int]:
					countryname: [list]
					[int]: string #ex:[0] US

					commonName: [list]
					[int]: string #ex:[0] DigiCert SHA2 Secure Server CA

					organizationName: [list]
					[int]: string #ex:[0] DigiCert Inc
				
				position: string #ex: leaf
				
				sha1Fingerprint: string #ex: 9e0c9ca295cfcd94bf8f643bcee3f0044ec98087

		certificateValidation

		ocspStapling: [list]
		[int]:
			oscpResponse: [list]
			[int]:
				responseType: [list]
				[int]: string #ex:[0] Basic OCSP Response

				responderID: [list]
				[int]: string #ex:[0] 0F80611C823161D52F28E78D4638B42CE1C6D9E2

				responses: [list]
				[int]:
					listEntry: [list]
					[int]:
						nextUpdate: [list]
						[int]: string #ex:[0] Oct 28 08:06:00 2015 GMT

						certID: [list]
						[int]:
							hashAlgorithm: [list]
							[int]: string #ex:[0] sha1

							serialNumber: [list]
							[int]: string #ex:[0] 0273213B48220C3CE06B4560AF04455B
							
							issuerNameHash: [list]
							[int]: string #ex:[0] 105FA67A80089DB5279F35CE830B43889EA3C70D
							
							issuerKeyHash: [list]
							[int]: string #ex:[0] 0F80611C823161D52F28E78D4638B42CE1C6D9E2
						
						thisUpdate: [list]
						[int]: string #ex:[0] Oct 21 08:51:00 2015 GMT
						
						certStatus: [list]
						[int]: string #ex:[0] good

				version: [list]
				[int]: string #ex:[0] 1

				responseStatus: [list]
				[int]: string #ex:[0] successful

				producedAt: [list]
				[int]: string #ex:[0] Oct 21 08:51:00 2015 GMT

				isTrustedByMozillaCAStore: True/False

			isSupported: True/False

		argument: string #ex: full

		title: string #ex: Certificate Information

	#Tests for Deflate Compression
	compression: [list] 
	[int]:
		compressionMethod: [list]
		[int]:
			isSupported: True/False
			type: string #ex: DEFLATE

		title: string #ex: Deflate Compression

	#Tests for the OpenSSL Heartbleed vulnerability
	heartbleed: [list] 
	[int]:
		openSslHeartbleed: [list]
		[int]:
			isVulnerable: True/False
		title: string #ex: OpenSSL Heartbleed

	#Tests HTTP Strict-Transport-Security field
	hsts: [list]
	[int]:
		httpStrictTransportSecurity: [list]
		[int]:
			isSupported: True/False
		title: string #ex: HTTP Strict Transport Security

	#Tests client-initiated renegotiation and secure renegotiation
	reneg: [list]
	[int]:
		sessionRenegotiation: [list]
		[int]:
			canBeClientInitiated: True/False
			isSecure: True/False
		title: string #ex: Session Renegotiation

	#Analyzes the SSL session resumption capabilities
	resum: [list]
	[int]:
		sessionResumptionWithSessionIDs: [list]
		[int]:
			errors:	string #ex: 0
			failedAttempts:	string #ex: 0
			isSupported: True/False	
			successfulAttempts:	string #ex: 5
			totalAttempts: string  #ex: 5
		sessionResumptionWithTLSTickets: [list]
		[int]:
			isSupported: True/False
			reason: string # ex: "TLS ticket not assigned"
		title: string #ex: Session Resumption

	#SSL 2.0 OpenSSL cipher
	sslv2: [list]
	<*1>
	
	#SSL 2.0 OpenSSL cipher
	sslv3: [list] 
	<*1>

	#TLS 1.0 OpenSSL cipher
	tslv1: [list]
	<*1>

	#TLS 1.1 OpenSSL cipher
	tlsv1_1: [list]
	<*1>

	#TLS 1.2 OpenSSL cipher
	tlsv1_2: [list]
	<*1>
```

### \<*1\> Same part for all openSSL Ciphers testes

```python
[int]:

	erros: [list]
	[int]: string #ex: ""

	rejectedCipherSuites: [list]
	[int]:
		cipherSuite: [list]
		[int]:
			anonymous: True/False
			connectionStatus: string #ex: TLS / Alert handshake failure
			name: string #ex: ADF-AES128-GCM-SHA256

	acceptedCipherSuites: [list]
	[int]:
		["" OR cipherSuite]: [list]
		[int]:
			[keyExchange]: [list]
			[int]:
                [A]: string #ex: 2
                [B]: string #ex: 1024
                [Cofactor]: string #ex: 1
                [Field_Type]: string #ex: prime-field
                Generator: string #ex: 0x008094456061..
                [GeneratorType]: string #ex: uncompressed 
                GroupSize: string #ex: 256
                [Order]: string #ex: 0x00fff..
                [prime OR Prime]: string #ex: 0x00ffff..
                [Seed]: string #ex: 0xc49d3..
                Type: string #ex: ECDH

			anonymous: True/False
			connectionStatus: string 
			keySize: string #ex: 128
			name: string #ex: AES128-GCM-SHA256

	preferredCipherSuite: [list]
	[int]:
		["" OR cipherSuite]: [list]
		[int]:
			keyExchange: [list]
			[int]:
				A: string #ex: 2
				B: string #ex: 1024
				Cofactor: string #ex: 1
				Field_Type: string #ex: prime-field
				Generator: string #ex: 0x008094456061..
				GeneratorType: string #ex: uncompressed	
				GroupSize: string #ex: 256
				Order: string #ex: 0x00fff..
				Prime: string #ex: 0x00ffff..
				Seed: string #ex: 0xc49d3..
				Type: string #ex: ECDH

			anonymous: True/False
			connectionStatus: string 
			keySize: string #ex: 128
			name: string #ECDHE-RSA-AES128-GCM-SHA256

	isProtocolSupported: True/False
	title: string 
		#ex: SSLV2 Cipher Suites
		#ex: SSLV3 Cipher Suites
		#ex: TLSV1 Cipher Suites
		#ex: TLSV1_1 Cipher Suites
		#ex: TLSV1_2 Cipher Suites
```


# Example:

## xxx.xxx.x.xxx:xxx


```json
{
   "ip": "xxx.xxx.x.xxx:xxx",
  "ipv6": "xxxx:xxxx:xxxx:xxx::xx",
  "port": "587",
  "host": "smtp.gmail.com",
  "data": {
    "certinfo": [
      {
        "certificateChain": [
          {
            "certificate": [
              {
                "asPEM": [
                  "-----BEGIN CERTIFICATE-----\nMIIEgDCCA2igAwIBAgIICmgx6TWoFA8wDQYJKoZIhvcNAQELBQAwSTELMAkGA1UE\nBhMCVVMxEzARBgNVBAoTCkdvb2dsZSBJbmMxJTAjBgNVBAMTHEdvb2dsZSBJbnRl\ncm5ldCBBdXRob3JpdHkgRzIwHhcNMTUxMDEzMjMzMTI2WhcNMTYxMDEyMDAwMDAw\nWjBoMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwN\nTW91bnRhaW4gVmlldzETMBEGA1UECgwKR29vZ2xlIEluYzEXMBUGA1UEAwwOc210\ncC5nbWFpbC5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDW63AE\nNh2d1KYcUmYl0TD8llIJsuegIKApJ9U3GCV+SXSppVG3X3BgNm4HVkyA96udTrUi\n4YI7na3ngGHPz83f+ioJjSQeahkA0zn7pu4rgrR2LHSZ7op8n4NfAYKebVHrdzNz\n23+QWA8bniningfzY9XHci7rc+MPBQoDI9e1oCuhjL+poEVi6Tb2GksGLj4ofMTn\nUQFlAcUmi3EYbdCPd9MGooTHQJhUD+9f653bbm1C/wgBnU1JagSD9tsy+8Sx/45N\n8Ehx1NrgBYG86OxxdC2YGHdhgVuD+zBrU5qwggp00K7/Q0K/XQBAaEusi7r91QXV\n8DM8NG1aVjab4BCnAgMBAAGjggFLMIIBRzAdBgNVHSUEFjAUBggrBgEFBQcDAQYI\nKwYBBQUHAwIwGQYDVR0RBBIwEIIOc210cC5nbWFpbC5jb20waAYIKwYBBQUHAQEE\nXDBaMCsGCCsGAQUFBzAChh9odHRwOi8vcGtpLmdvb2dsZS5jb20vR0lBRzIuY3J0\nMCsGCCsGAQUFBzABhh9odHRwOi8vY2xpZW50czEuZ29vZ2xlLmNvbS9vY3NwMB0G\nA1UdDgQWBBTzUZXtqQ4lQTk+WmWs6PDxZ5CX8TAMBgNVHRMBAf8EAjAAMB8GA1Ud\nIwQYMBaAFErdBhYbvPZotXb1gba7Yhq6WoEvMCEGA1UdIAQaMBgwDAYKKwYBBAHW\neQIFATAIBgZngQwBAgIwMAYDVR0fBCkwJzAloCOgIYYfaHR0cDovL3BraS5nb29n\nbGUuY29tL0dJQUcyLmNybDANBgkqhkiG9w0BAQsFAAOCAQEAeQSXqjPeIEFfhlG2\n/ZC4WovEIN8k/5kOYaQTxlYmTjeeCrM3w198cnosfZfiTDWOeDjwovbrUar+Ci3l\nMWjniAmTGTyDQnsEqzt6lxUYXgpwk10afLH3HZrHuYME+cRvM+BBuULR5C0Ct1tJ\nt2jAdNbfcPLiTsyChJqXe/ykxq3OPGIzd5SG52uIIjEhpnfYqYiOLk3A9CTBmhNA\ncGmaBr7b7YTOisGpQSB6EqkhkrCyG/fm18THsWQw6FJdv09+T6eloaFWbFw9uIke\nsPOXg6W1t4a36kl4K/F5/Qfh6XJWB4lWw5dw2QrkkbxbFEFO0lWY2od+LlaBNz8y\ncvDlRw==\n-----END CERTIFICATE-----"
                ],
                "subjectPublicKeyInfo": [
                  {
                    "publicKey": [
                      {
                        "modulus": [
                          "00:d6:eb:70:04:36:1d:9d:d4:a6:1c:52:66:25:d1:30:fc:96:52:09:b2:e7:a0:20:a0:29:27:d5:37:18:25:7e:49:74:a9:a5:51:b7:5f:70:60:36:6e:07:56:4c:80:f7:ab:9d:4e:b5:22:e1:82:3b:9d:ad:e7:80:61:cf:cf:cd:df:fa:2a:09:8d:24:1e:6a:19:00:d3:39:fb:a6:ee:2b:82:b4:76:2c:74:99:ee:8a:7c:9f:83:5f:01:82:9e:6d:51:eb:77:33:73:db:7f:90:58:0f:1b:9e:29:e2:9e:07:f3:63:d5:c7:72:2e:eb:73:e3:0f:05:0a:03:23:d7:b5:a0:2b:a1:8c:bf:a9:a0:45:62:e9:36:f6:1a:4b:06:2e:3e:28:7c:c4:e7:51:01:65:01:c5:26:8b:71:18:6d:d0:8f:77:d3:06:a2:84:c7:40:98:54:0f:ef:5f:eb:9d:db:6e:6d:42:ff:08:01:9d:4d:49:6a:04:83:f6:db:32:fb:c4:b1:ff:8e:4d:f0:48:71:d4:da:e0:05:81:bc:e8:ec:71:74:2d:98:18:77:61:81:5b:83:fb:30:6b:53:9a:b0:82:0a:74:d0:ae:ff:43:42:bf:5d:00:40:68:4b:ac:8b:ba:fd:d5:05:d5:f0:33:3c:34:6d:5a:56:36:9b:e0:10:a7"
                        ],
                        "exponent": [
                          "65537"
                        ]
                      }
                    ],
                    "publicKeyAlgorithm": [
                      "rsaEncryption"
                    ],
                    "publicKeySize": [
                      "2048"
                    ]
                  }
                ],
                "version": [
                  "2"
                ],
                "extensions": [
                  {
                    "X509v3SubjectKeyIdentifier": [
                      "F3:51:95:ED:A9:0E:25:41:39:3E:5A:65:AC:E8:F0:F1:67:90:97:F1"
                    ],
                    "X509v3ExtendedKeyUsage": [
                      {
                        "TLSWebClientAuthentication": [
                          ""
                        ],
                        "TLSWebServerAuthentication": [
                          ""
                        ]
                      }
                    ],
                    "AuthorityInformationAccess": [
                      {
                        "CAIssuers": [
                          {
                            "URI": [
                              {
                                "listEntry": [
                                  "http://pki.google.com/GIAG2.crt"
                                ]
                              }
                            ]
                          }
                        ],
                        "OCSP": [
                          {
                            "URI": [
                              {
                                "listEntry": [
                                  "http://clients1.google.com/ocsp"
                                ]
                              }
                            ]
                          }
                        ]
                      }
                    ],
                    "X509v3CRLDistributionPoints": [
                      {
                        "FullName": [
                          {
                            "listEntry": [
                              ""
                            ]
                          }
                        ],
                        "URI": [
                          {
                            "listEntry": [
                              "http://pki.google.com/GIAG2.crl"
                            ]
                          }
                        ]
                      }
                    ],
                    "X509v3BasicConstraints": [
                      "CA:FALSE"
                    ],
                    "X509v3SubjectAlternativeName": [
                      {
                        "DNS": [
                          {
                            "listEntry": [
                              "smtp.gmail.com"
                            ]
                          }
                        ]
                      }
                    ],
                    "X509v3AuthorityKeyIdentifier": [
                      "keyid:4A:DD:06:16:1B:BC:F6:68:B5:76:F5:81:B6:BB:62:1A:BA:5A:81:2F"
                    ],
                    "X509v3CertificatePolicies": [
                      {
                        "Policy": [
                          {
                            "listEntry": [
                              "1.3.6.1.4.1.11129.2.5.1",
                              "2.23.140.1.2.2"
                            ]
                          }
                        ]
                      }
                    ]
                  }
                ],
                "signatureValue": [
                  "79:04:97:aa:33:de:20:41:5f:86:51:b6:fd:90:b8:5a:8b:c4:20:df:24:ff:99:0e:61:a4:13:c6:56:26:4e:37:9e:0a:b3:37:c3:5f:7c:72:7a:2c:7d:97:e2:4c:35:8e:78:38:f0:a2:f6:eb:51:aa:fe:0a:2d:e5:31:68:e7:88:09:93:19:3c:83:42:7b:04:ab:3b:7a:97:15:18:5e:0a:70:93:5d:1a:7c:b1:f7:1d:9a:c7:b9:83:04:f9:c4:6f:33:e0:41:b9:42:d1:e4:2d:02:b7:5b:49:b7:68:c0:74:d6:df:70:f2:e2:4e:cc:82:84:9a:97:7b:fc:a4:c6:ad:ce:3c:62:33:77:94:86:e7:6b:88:22:31:21:a6:77:d8:a9:88:8e:2e:4d:c0:f4:24:c1:9a:13:40:70:69:9a:06:be:db:ed:84:ce:8a:c1:a9:41:20:7a:12:a9:21:92:b0:b2:1b:f7:e6:d7:c4:c7:b1:64:30:e8:52:5d:bf:4f:7e:4f:a7:a5:a1:a1:56:6c:5c:3d:b8:89:1e:b0:f3:97:83:a5:b5:b7:86:b7:ea:49:78:2b:f1:79:fd:07:e1:e9:72:56:07:89:56:c3:97:70:d9:0a:e4:91:bc:5b:14:41:4e:d2:55:98:da:87:7e:2e:56:81:37:3f:32:72:f0:e5:47"
                ],
                "signatureAlgorithm": [
                  "sha256WithRSAEncryption"
                ],
                "serialNumber": [
                  "0A6831E935A8140F"
                ],
                "subject": [
                  {
                    "countryName": [
                      "US"
                    ],
                    "commonName": [
                      "smtp.gmail.com"
                    ],
                    "organizationName": [
                      "Google Inc"
                    ],
                    "localityName": [
                      "Mountain View"
                    ],
                    "stateOrProvinceName": [
                      "California"
                    ]
                  }
                ],
                "validity": [
                  {
                    "notAfter": [
                      "Oct 12 00:00:00 2016 GMT"
                    ],
                    "notBefore": [
                      "Oct 13 23:31:26 2015 GMT"
                    ]
                  }
                ],
                "issuer": [
                  {
                    "countryName": [
                      "US"
                    ],
                    "commonName": [
                      "Google Internet Authority G2"
                    ],
                    "organizationName": [
                      "Google Inc"
                    ]
                  }
                ],
                "position": "leaf",
                "sha1Fingerprint": "41d485e1fc1b1d3a2d60e351abe64aa452d8cf00"
              },
              {
                "asPEM": [
                  "-----BEGIN CERTIFICATE-----\nMIID8DCCAtigAwIBAgIDAjqDMA0GCSqGSIb3DQEBCwUAMEIxCzAJBgNVBAYTAlVT\nMRYwFAYDVQQKEw1HZW9UcnVzdCBJbmMuMRswGQYDVQQDExJHZW9UcnVzdCBHbG9i\nYWwgQ0EwHhcNMTMwNDA1MTUxNTU2WhcNMTYxMjMxMjM1OTU5WjBJMQswCQYDVQQG\nEwJVUzETMBEGA1UEChMKR29vZ2xlIEluYzElMCMGA1UEAxMcR29vZ2xlIEludGVy\nbmV0IEF1dGhvcml0eSBHMjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB\nAJwqBHdc2FCROgajguDYUEi8iT/xGXAaiEZ+4I/F8YnOIe5a/mENtzJEiaB0C1NP\nVaTOgmKV7utZX8bhBYASxF6UP7xbSDj0U/ck5vuR6RXEz/RTDfRK/J9U3n2+oGtv\nh8DQUB8oMANA2ghzUWx//zo8pzcGjr1LEQTrfSTe5vn8MXH7lNVg8y5Kr0LSy+rE\nahqyzFPdFUuLH8gZYR/Nnag+YyuENWllhMgZxUYi+FOVvuOAShDGKuy6lyARxzmZ\nEASg8GF6lSWMTlJ14rbtCMoU/M4iarNOz0YDl5cDfsCx3nuvRTPPuj5xt970JSXC\nDTWJnZ37DhF5iR43xa+OcmkCAwEAAaOB5zCB5DAfBgNVHSMEGDAWgBTAephojYn7\nqwVkDBF9qn1luMrMTjAdBgNVHQ4EFgQUSt0GFhu89mi1dvWBtrtiGrpagS8wDgYD\nVR0PAQH/BAQDAgEGMC4GCCsGAQUFBwEBBCIwIDAeBggrBgEFBQcwAYYSaHR0cDov\nL2cuc3ltY2QuY29tMBIGA1UdEwEB/wQIMAYBAf8CAQAwNQYDVR0fBC4wLDAqoCig\nJoYkaHR0cDovL2cuc3ltY2IuY29tL2NybHMvZ3RnbG9iYWwuY3JsMBcGA1UdIAQQ\nMA4wDAYKKwYBBAHWeQIFATANBgkqhkiG9w0BAQsFAAOCAQEAqvqpIM1qZ4PtXtR+\n3h3Ef+AlBgDFJPupyC1tft6dgmUsgWM0Zj7pUsIItMsv91+ZOmqcUHqFBYx90SpI\nhNMJbHzCzTWf84LuUt5oX+QAihcglvcpjZpNy6jehsgNb1aHA30DP9z6eX0hGfnI\nOi9RdozHQZJxjyXON/hKTAAj78Q1EK7gI4BzfE00LshukNYQHpmEcxpw8u1VDu4X\nBupn7jLrLN1nBz/2i8Jw3lsA5rsb0zYaImxssDVCbJAJPZPpZAkiDoUGn8JzIdPm\nX4DkjYUiOnMDsWCOrmji9D6X52ASCWg23jrW4kOVWzeBkoEfu43XrVJkFleW2V40\nfsg12A==\n-----END CERTIFICATE-----"
                ],
                "subjectPublicKeyInfo": [
                  {
                    "publicKey": [
                      {
                        "modulus": [
                          "00:9c:2a:04:77:5c:d8:50:91:3a:06:a3:82:e0:d8:50:48:bc:89:3f:f1:19:70:1a:88:46:7e:e0:8f:c5:f1:89:ce:21:ee:5a:fe:61:0d:b7:32:44:89:a0:74:0b:53:4f:55:a4:ce:82:62:95:ee:eb:59:5f:c6:e1:05:80:12:c4:5e:94:3f:bc:5b:48:38:f4:53:f7:24:e6:fb:91:e9:15:c4:cf:f4:53:0d:f4:4a:fc:9f:54:de:7d:be:a0:6b:6f:87:c0:d0:50:1f:28:30:03:40:da:08:73:51:6c:7f:ff:3a:3c:a7:37:06:8e:bd:4b:11:04:eb:7d:24:de:e6:f9:fc:31:71:fb:94:d5:60:f3:2e:4a:af:42:d2:cb:ea:c4:6a:1a:b2:cc:53:dd:15:4b:8b:1f:c8:19:61:1f:cd:9d:a8:3e:63:2b:84:35:69:65:84:c8:19:c5:46:22:f8:53:95:be:e3:80:4a:10:c6:2a:ec:ba:97:20:11:c7:39:99:10:04:a0:f0:61:7a:95:25:8c:4e:52:75:e2:b6:ed:08:ca:14:fc:ce:22:6a:b3:4e:cf:46:03:97:97:03:7e:c0:b1:de:7b:af:45:33:cf:ba:3e:71:b7:de:f4:25:25:c2:0d:35:89:9d:9d:fb:0e:11:79:89:1e:37:c5:af:8e:72:69"
                        ],
                        "exponent": [
                          "65537"
                        ]
                      }
                    ],
                    "publicKeyAlgorithm": [
                      "rsaEncryption"
                    ],
                    "publicKeySize": [
                      "2048"
                    ]
                  }
                ],
                "version": [
                  "2"
                ],
                "extensions": [
                  {
                    "X509v3SubjectKeyIdentifier": [
                      "4A:DD:06:16:1B:BC:F6:68:B5:76:F5:81:B6:BB:62:1A:BA:5A:81:2F"
                    ],
                    "AuthorityInformationAccess": [
                      {
                        "OCSP": [
                          {
                            "URI": [
                              {
                                "listEntry": [
                                  "http://g.symcd.com"
                                ]
                              }
                            ]
                          }
                        ]
                      }
                    ],
                    "X509v3CRLDistributionPoints": [
                      {
                        "FullName": [
                          {
                            "listEntry": [
                              ""
                            ]
                          }
                        ],
                        "URI": [
                          {
                            "listEntry": [
                              "http://g.symcb.com/crls/gtglobal.crl"
                            ]
                          }
                        ]
                      }
                    ],
                    "X509v3BasicConstraints": [
                      "CA:TRUE, pathlen:0"
                    ],
                    "X509v3KeyUsage": [
                      {
                        "CRLSign": [
                          ""
                        ],
                        "CertificateSign": [
                          ""
                        ]
                      }
                    ],
                    "X509v3AuthorityKeyIdentifier": [
                      "keyid:C0:7A:98:68:8D:89:FB:AB:05:64:0C:11:7D:AA:7D:65:B8:CA:CC:4E"
                    ],
                    "X509v3CertificatePolicies": [
                      {
                        "Policy": [
                          {
                            "listEntry": [
                              "1.3.6.1.4.1.11129.2.5.1"
                            ]
                          }
                        ]
                      }
                    ]
                  }
                ],
                "signatureValue": [
                  "aa:fa:a9:20:cd:6a:67:83:ed:5e:d4:7e:de:1d:c4:7f:e0:25:06:00:c5:24:fb:a9:c8:2d:6d:7e:de:9d:82:65:2c:81:63:34:66:3e:e9:52:c2:08:b4:cb:2f:f7:5f:99:3a:6a:9c:50:7a:85:05:8c:7d:d1:2a:48:84:d3:09:6c:7c:c2:cd:35:9f:f3:82:ee:52:de:68:5f:e4:00:8a:17:20:96:f7:29:8d:9a:4d:cb:a8:de:86:c8:0d:6f:56:87:03:7d:03:3f:dc:fa:79:7d:21:19:f9:c8:3a:2f:51:76:8c:c7:41:92:71:8f:25:ce:37:f8:4a:4c:00:23:ef:c4:35:10:ae:e0:23:80:73:7c:4d:34:2e:c8:6e:90:d6:10:1e:99:84:73:1a:70:f2:ed:55:0e:ee:17:06:ea:67:ee:32:eb:2c:dd:67:07:3f:f6:8b:c2:70:de:5b:00:e6:bb:1b:d3:36:1a:22:6c:6c:b0:35:42:6c:90:09:3d:93:e9:64:09:22:0e:85:06:9f:c2:73:21:d3:e6:5f:80:e4:8d:85:22:3a:73:03:b1:60:8e:ae:68:e2:f4:3e:97:e7:60:12:09:68:36:de:3a:d6:e2:43:95:5b:37:81:92:81:1f:bb:8d:d7:ad:52:64:16:57:96:d9:5e:34:7e:c8:35:d8"
                ],
                "signatureAlgorithm": [
                  "sha256WithRSAEncryption"
                ],
                "serialNumber": [
                  "023A83"
                ],
                "subject": [
                  {
                    "countryName": [
                      "US"
                    ],
                    "commonName": [
                      "Google Internet Authority G2"
                    ],
                    "organizationName": [
                      "Google Inc"
                    ]
                  }
                ],
                "validity": [
                  {
                    "notAfter": [
                      "Dec 31 23:59:59 2016 GMT"
                    ],
                    "notBefore": [
                      "Apr  5 15:15:56 2013 GMT"
                    ]
                  }
                ],
                "issuer": [
                  {
                    "countryName": [
                      "US"
                    ],
                    "commonName": [
                      "GeoTrust Global CA"
                    ],
                    "organizationName": [
                      "GeoTrust Inc."
                    ]
                  }
                ],
                "position": "intermediate",
                "sha1Fingerprint": "178f7e93a74ed73d88c29042220b9ae6e4b371cd"
              },
              {
                "asPEM": [
                  "-----BEGIN CERTIFICATE-----\nMIIDfTCCAuagAwIBAgIDErvmMA0GCSqGSIb3DQEBBQUAME4xCzAJBgNVBAYTAlVT\nMRAwDgYDVQQKEwdFcXVpZmF4MS0wKwYDVQQLEyRFcXVpZmF4IFNlY3VyZSBDZXJ0\naWZpY2F0ZSBBdXRob3JpdHkwHhcNMDIwNTIxMDQwMDAwWhcNMTgwODIxMDQwMDAw\nWjBCMQswCQYDVQQGEwJVUzEWMBQGA1UEChMNR2VvVHJ1c3QgSW5jLjEbMBkGA1UE\nAxMSR2VvVHJ1c3QgR2xvYmFsIENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB\nCgKCAQEA2swYYzD99BcjGlZ+W988bDjkcbd4kdS8odhM+KhDtgPpTSEHCIjaWC9m\nOSm9BXiLnTjoBbdqfnGk5sRgprDvgOSJKA+eJdbtg/OtppHHmMlCGDUUna2YRpIu\nT8rxh0PBFpVXLVDviS2Aelet8u5fa9IAjbkU+BQVNdnARqN7csiRv8lVK83Qlz6c\nJmTM386DGXHKTubU1XupGc1V3sjs0l44U+VcT4wt/lAjNvxm5suOpDkZALeVAjmR\nCw7+OC7RHQWa9k0+bw8HHa8sHo9gOeL6NlMTOdReJivbPagUvTLrGAMoUgRx5asz\nPeE4uwc2hGKceeoWMPRfwCvocWvk+QIDAQABo4HwMIHtMB8GA1UdIwQYMBaAFEjm\naPkr0rKV10fYIyAQTzOYkJ/UMB0GA1UdDgQWBBTAephojYn7qwVkDBF9qn1luMrM\nTjAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjA6BgNVHR8EMzAxMC+g\nLaArhilodHRwOi8vY3JsLmdlb3RydXN0LmNvbS9jcmxzL3NlY3VyZWNhLmNybDBO\nBgNVHSAERzBFMEMGBFUdIAAwOzA5BggrBgEFBQcCARYtaHR0cHM6Ly93d3cuZ2Vv\ndHJ1c3QuY29tL3Jlc291cmNlcy9yZXBvc2l0b3J5MA0GCSqGSIb3DQEBBQUAA4GB\nAHbhEm5OSxYShjAGsoEIz/AIx8dxfmbuwu3UOx//8PDITtZDOLC5MH0Y0FWDomrL\nNhGc6Ehmo21/uBPUR/6LWlxz/K7ZGzIZOKuXNBSqltLroxwUCEm2u+WR74M26x1W\nb8ravHNjkOR/ez4iyz0H7V84dJzjA1BOoa+Y7mHyhD8S\n-----END CERTIFICATE-----"
                ],
                "subjectPublicKeyInfo": [
                  {
                    "publicKey": [
                      {
                        "modulus": [
                          "00:da:cc:18:63:30:fd:f4:17:23:1a:56:7e:5b:df:3c:6c:38:e4:71:b7:78:91:d4:bc:a1:d8:4c:f8:a8:43:b6:03:e9:4d:21:07:08:88:da:58:2f:66:39:29:bd:05:78:8b:9d:38:e8:05:b7:6a:7e:71:a4:e6:c4:60:a6:b0:ef:80:e4:89:28:0f:9e:25:d6:ed:83:f3:ad:a6:91:c7:98:c9:42:18:35:14:9d:ad:98:46:92:2e:4f:ca:f1:87:43:c1:16:95:57:2d:50:ef:89:2d:80:7a:57:ad:f2:ee:5f:6b:d2:00:8d:b9:14:f8:14:15:35:d9:c0:46:a3:7b:72:c8:91:bf:c9:55:2b:cd:d0:97:3e:9c:26:64:cc:df:ce:83:19:71:ca:4e:e6:d4:d5:7b:a9:19:cd:55:de:c8:ec:d2:5e:38:53:e5:5c:4f:8c:2d:fe:50:23:36:fc:66:e6:cb:8e:a4:39:19:00:b7:95:02:39:91:0b:0e:fe:38:2e:d1:1d:05:9a:f6:4d:3e:6f:0f:07:1d:af:2c:1e:8f:60:39:e2:fa:36:53:13:39:d4:5e:26:2b:db:3d:a8:14:bd:32:eb:18:03:28:52:04:71:e5:ab:33:3d:e1:38:bb:07:36:84:62:9c:79:ea:16:30:f4:5f:c0:2b:e8:71:6b:e4:f9"
                        ],
                        "exponent": [
                          "65537"
                        ]
                      }
                    ],
                    "publicKeyAlgorithm": [
                      "rsaEncryption"
                    ],
                    "publicKeySize": [
                      "2048"
                    ]
                  }
                ],
                "version": [
                  "2"
                ],
                "extensions": [
                  {
                    "X509v3SubjectKeyIdentifier": [
                      "C0:7A:98:68:8D:89:FB:AB:05:64:0C:11:7D:AA:7D:65:B8:CA:CC:4E"
                    ],
                    "X509v3CRLDistributionPoints": [
                      {
                        "FullName": [
                          {
                            "listEntry": [
                              ""
                            ]
                          }
                        ],
                        "URI": [
                          {
                            "listEntry": [
                              "http://crl.geotrust.com/crls/secureca.crl"
                            ]
                          }
                        ]
                      }
                    ],
                    "X509v3BasicConstraints": [
                      "CA:TRUE"
                    ],
                    "X509v3KeyUsage": [
                      {
                        "CRLSign": [
                          ""
                        ],
                        "CertificateSign": [
                          ""
                        ]
                      }
                    ],
                    "X509v3AuthorityKeyIdentifier": [
                      "keyid:48:E6:68:F9:2B:D2:B2:95:D7:47:D8:23:20:10:4F:33:98:90:9F:D4"
                    ],
                    "X509v3CertificatePolicies": [
                      {
                        "Policy": [
                          {
                            "listEntry": [
                              "X509v3 Any Policy"
                            ]
                          }
                        ],
                        "CPS": [
                          {
                            "listEntry": [
                              "https://www.geotrust.com/resources/repository"
                            ]
                          }
                        ]
                      }
                    ]
                  }
                ],
                "signatureValue": [
                  "76:e1:12:6e:4e:4b:16:12:86:30:06:b2:81:08:cf:f0:08:c7:c7:71:7e:66:ee:c2:ed:d4:3b:1f:ff:f0:f0:c8:4e:d6:43:38:b0:b9:30:7d:18:d0:55:83:a2:6a:cb:36:11:9c:e8:48:66:a3:6d:7f:b8:13:d4:47:fe:8b:5a:5c:73:fc:ae:d9:1b:32:19:38:ab:97:34:14:aa:96:d2:eb:a3:1c:14:08:49:b6:bb:e5:91:ef:83:36:eb:1d:56:6f:ca:da:bc:73:63:90:e4:7f:7b:3e:22:cb:3d:07:ed:5f:38:74:9c:e3:03:50:4e:a1:af:98:ee:61:f2:84:3f:12"
                ],
                "signatureAlgorithm": [
                  "sha1WithRSAEncryption"
                ],
                "serialNumber": [
                  "12BBE6"
                ],
                "subject": [
                  {
                    "countryName": [
                      "US"
                    ],
                    "commonName": [
                      "GeoTrust Global CA"
                    ],
                    "organizationName": [
                      "GeoTrust Inc."
                    ]
                  }
                ],
                "validity": [
                  {
                    "notAfter": [
                      "Aug 21 04:00:00 2018 GMT"
                    ],
                    "notBefore": [
                      "May 21 04:00:00 2002 GMT"
                    ]
                  }
                ],
                "issuer": [
                  {
                    "countryName": [
                      "US"
                    ],
                    "organizationalUnitName": [
                      "Equifax Secure Certificate Authority"
                    ],
                    "organizationName": [
                      "Equifax"
                    ]
                  }
                ],
                "position": "intermediate",
                "sha1Fingerprint": "7359755c6df9a0abc3060bce369564c8ec4542a3"
              }
            ]
          }
        ],
        "certificateValidation": [
          {
            "hostnameValidation": [
              {
                "certificateMatchesServerHostname": "True",
                "serverHostname": "smtp.gmail.com"
              }
            ],
            "pathValidation": [
              {
                "trustStoreVersion": "09/2015",
                "usingTrustStore": "Google",
                "validationResult": "ok"
              },
              {
                "trustStoreVersion": "Update 65",
                "usingTrustStore": "Java 6",
                "validationResult": "ok"
              },
              {
                "trustStoreVersion": "09/2015",
                "usingTrustStore": "Microsoft",
                "validationResult": "ok"
              },
              {
                "trustStoreVersion": "OS X 10.10.5",
                "usingTrustStore": "Apple",
                "validationResult": "ok"
              },
              {
                "trustStoreVersion": "09/2015",
                "usingTrustStore": "Mozilla NSS",
                "validationResult": "ok"
              }
            ]
          }
        ],
        "ocspStapling": [
          {
            "isSupported": "False"
          }
        ],
        "argument": "full",
        "title": "Certificate Information"
      }
    ],
    "compression": [
      {
        "compressionMethod": [
          {
            "isSupported": "False",
            "type": "DEFLATE"
          }
        ],
        "title": "Deflate Compression"
      }
    ],
    "heartbleed": [
      {
        "openSslHeartbleed": [
          {
            "isVulnerable": "False"
          }
        ],
        "title": "OpenSSL Heartbleed"
      }
    ],
    "hsts": [
      {
        "exception": "exceptions.Exception - Cannot use --hsts with --starttls.",
        "title": "PluginHSTS"
      }
    ],
    "reneg": [
      {
        "sessionRenegotiation": [
          {
            "canBeClientInitiated": "False",
            "isSecure": "True"
          }
        ],
        "title": "Session Renegotiation"
      }
    ],
    "resum": [
      {
        "sessionResumptionWithSessionIDs": [
          {
            "errors": "0",
            "failedAttempts": "5",
            "isSupported": "False",
            "successfulAttempts": "0",
            "totalAttempts": "5"
          }
        ],
        "sessionResumptionWithTLSTickets": [
          {
            "isSupported": "True"
          }
        ],
        "title": "Session Resumption"
      }
    ],
    "sslv2": [
      {
        "errors": [
          ""
        ],
        "rejectedCipherSuites": [
          {
            "cipherSuite": [
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Unexpected EOF",
                "name": "DES-CBC-MD5"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Unexpected EOF",
                "name": "DES-CBC3-MD5"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Unexpected EOF",
                "name": "EXP-RC2-CBC-MD5"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Unexpected EOF",
                "name": "EXP-RC4-MD5"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Unexpected EOF",
                "name": "IDEA-CBC-MD5"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Unexpected EOF",
                "name": "RC2-CBC-MD5"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Unexpected EOF",
                "name": "RC4-MD5"
              }
            ]
          }
        ],
        "acceptedCipherSuites": [
          ""
        ],
        "preferredCipherSuite": [
          ""
        ],
        "isProtocolSupported": "False",
        "title": "SSLV2 Cipher Suites"
      }
    ],
    "sslv3": [
      {
        "errors": [
          ""
        ],
        "rejectedCipherSuites": [
          {
            "cipherSuite": [
              {
                "anonymous": "True",
                "connectionStatus": "TLS / No ciphers available",
                "name": "ADH-AES128-GCM-SHA256"
              },
              {
                "anonymous": "True",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ADH-AES128-SHA"
              },
              {
                "anonymous": "True",
                "connectionStatus": "TLS / No ciphers available",
                "name": "ADH-AES128-SHA256"
              },
              {
                "anonymous": "True",
                "connectionStatus": "TLS / No ciphers available",
                "name": "ADH-AES256-GCM-SHA384"
              },
              {
                "anonymous": "True",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ADH-AES256-SHA"
              },
              {
                "anonymous": "True",
                "connectionStatus": "TLS / No ciphers available",
                "name": "ADH-AES256-SHA256"
              },
              {
                "anonymous": "True",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ADH-CAMELLIA128-SHA"
              },
              {
                "anonymous": "True",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ADH-CAMELLIA256-SHA"
              },
              {
                "anonymous": "True",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ADH-DES-CBC-SHA"
              },
              {
                "anonymous": "True",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ADH-DES-CBC3-SHA"
              },
              {
                "anonymous": "True",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ADH-RC4-MD5"
              },
              {
                "anonymous": "True",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ADH-SEED-SHA"
              },
              {
                "anonymous": "True",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "AECDH-AES128-SHA"
              },
              {
                "anonymous": "True",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "AECDH-AES256-SHA"
              },
              {
                "anonymous": "True",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "AECDH-DES-CBC3-SHA"
              },
              {
                "anonymous": "True",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "AECDH-NULL-SHA"
              },
              {
                "anonymous": "True",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "AECDH-RC4-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "AES128-GCM-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "AES128-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "AES256-GCM-SHA384"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "AES256-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "CAMELLIA128-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "CAMELLIA256-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DES-CBC-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "DH-DSS-AES128-GCM-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DH-DSS-AES128-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "DH-DSS-AES128-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "DH-DSS-AES256-GCM-SHA384"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DH-DSS-AES256-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "DH-DSS-AES256-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DH-DSS-CAMELLIA128-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DH-DSS-CAMELLIA256-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DH-DSS-DES-CBC-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DH-DSS-DES-CBC3-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DH-DSS-SEED-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "DH-RSA-AES128-GCM-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DH-RSA-AES128-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "DH-RSA-AES128-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "DH-RSA-AES256-GCM-SHA384"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DH-RSA-AES256-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "DH-RSA-AES256-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DH-RSA-CAMELLIA128-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DH-RSA-CAMELLIA256-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DH-RSA-DES-CBC-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DH-RSA-DES-CBC3-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DH-RSA-SEED-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "DHE-DSS-AES128-GCM-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DHE-DSS-AES128-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "DHE-DSS-AES128-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "DHE-DSS-AES256-GCM-SHA384"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DHE-DSS-AES256-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "DHE-DSS-AES256-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DHE-DSS-CAMELLIA128-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DHE-DSS-CAMELLIA256-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DHE-DSS-SEED-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "DHE-RSA-AES128-GCM-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DHE-RSA-AES128-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "DHE-RSA-AES128-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "DHE-RSA-AES256-GCM-SHA384"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DHE-RSA-AES256-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "DHE-RSA-AES256-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DHE-RSA-CAMELLIA128-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DHE-RSA-CAMELLIA256-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DHE-RSA-SEED-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "ECDH-ECDSA-AES128-GCM-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ECDH-ECDSA-AES128-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "ECDH-ECDSA-AES128-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "ECDH-ECDSA-AES256-GCM-SHA384"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ECDH-ECDSA-AES256-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "ECDH-ECDSA-AES256-SHA384"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ECDH-ECDSA-DES-CBC3-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ECDH-ECDSA-NULL-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ECDH-ECDSA-RC4-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "ECDH-RSA-AES128-GCM-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ECDH-RSA-AES128-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "ECDH-RSA-AES128-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "ECDH-RSA-AES256-GCM-SHA384"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ECDH-RSA-AES256-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "ECDH-RSA-AES256-SHA384"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ECDH-RSA-DES-CBC3-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ECDH-RSA-NULL-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ECDH-RSA-RC4-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "ECDHE-ECDSA-AES128-GCM-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ECDHE-ECDSA-AES128-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "ECDHE-ECDSA-AES128-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "ECDHE-ECDSA-AES256-GCM-SHA384"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ECDHE-ECDSA-AES256-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "ECDHE-ECDSA-AES256-SHA384"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ECDHE-ECDSA-DES-CBC3-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ECDHE-ECDSA-NULL-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ECDHE-ECDSA-RC4-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "ECDHE-RSA-AES128-GCM-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "ECDHE-RSA-AES128-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "ECDHE-RSA-AES256-GCM-SHA384"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "ECDHE-RSA-AES256-SHA384"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ECDHE-RSA-DES-CBC3-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ECDHE-RSA-NULL-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "EDH-DSS-DES-CBC-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "EDH-DSS-DES-CBC3-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "EDH-RSA-DES-CBC-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "EDH-RSA-DES-CBC3-SHA"
              },
              {
                "anonymous": "True",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "EXP-ADH-DES-CBC-SHA"
              },
              {
                "anonymous": "True",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "EXP-ADH-RC4-MD5"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "EXP-DES-CBC-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "EXP-EDH-DSS-DES-CBC-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "EXP-EDH-RSA-DES-CBC-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "EXP-RC2-CBC-MD5"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "EXP-RC4-MD5"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "IDEA-CBC-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "NULL-MD5"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "NULL-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "NULL-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "PSK-3DES-EDE-CBC-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "PSK-AES128-CBC-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "PSK-AES256-CBC-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "PSK-RC4-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "SEED-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "SRP-3DES-EDE-CBC-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "SRP-AES-128-CBC-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "SRP-AES-256-CBC-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "SRP-DSS-3DES-EDE-CBC-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "SRP-DSS-AES-128-CBC-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "SRP-DSS-AES-256-CBC-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "SRP-RSA-3DES-EDE-CBC-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "SRP-RSA-AES-128-CBC-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "SRP-RSA-AES-256-CBC-SHA"
              }
            ]
          }
        ],
        "acceptedCipherSuites": [
          {
            "cipherSuite": [
              {
                "anonymous": "False",
                "connectionStatus": "250 2.0.0 OK m137sm2473429wmb.2 - gsmtp",
                "keySize": "128",
                "name": "AES128-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "250 2.0.0 OK b12sm2462491wma.6 - gsmtp",
                "keySize": "256",
                "name": "AES256-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "250 2.0.0 OK at4sm6639894wjc.9 - gsmtp",
                "keySize": "112",
                "name": "DES-CBC3-SHA"
              },
              {
                "keyExchange": [
                  {
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
                  }
                ],
                "anonymous": "False",
                "connectionStatus": "250 2.0.0 OK t126sm2438827wmd.23 - gsmtp",
                "keySize": "128",
                "name": "ECDHE-RSA-AES128-SHA"
              },
              {
                "keyExchange": [
                  {
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
                  }
                ],
                "anonymous": "False",
                "connectionStatus": "250 2.0.0 OK e79sm2445400wmd.16 - gsmtp",
                "keySize": "256",
                "name": "ECDHE-RSA-AES256-SHA"
              },
              {
                "keyExchange": [
                  {
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
                  }
                ],
                "anonymous": "False",
                "connectionStatus": "250 2.0.0 OK l5sm6632988wjf.11 - gsmtp",
                "keySize": "128",
                "name": "ECDHE-RSA-RC4-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "250 2.0.0 OK t20sm2473650wme.0 - gsmtp",
                "keySize": "128",
                "name": "RC4-MD5"
              },
              {
                "anonymous": "False",
                "connectionStatus": "250 2.0.0 OK uj4sm6605103wjc.34 - gsmtp",
                "keySize": "128",
                "name": "RC4-SHA"
              }
            ]
          }
        ],
        "preferredCipherSuite": [
          {
            "cipherSuite": [
              {
                "keyExchange": [
                  {
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
                  }
                ],
                "anonymous": "False",
                "connectionStatus": "250 2.0.0 OK at4sm6639920wjc.9 - gsmtp",
                "keySize": "128",
                "name": "ECDHE-RSA-RC4-SHA"
              }
            ]
          }
        ],
        "isProtocolSupported": "True",
        "title": "SSLV3 Cipher Suites"
      }
    ],
    "tlsv1": [
      {
        "errors": [
          ""
        ],
        "rejectedCipherSuites": [
          {
            "cipherSuite": [
              {
                "anonymous": "True",
                "connectionStatus": "TLS / No ciphers available",
                "name": "ADH-AES128-GCM-SHA256"
              },
              {
                "anonymous": "True",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ADH-AES128-SHA"
              },
              {
                "anonymous": "True",
                "connectionStatus": "TLS / No ciphers available",
                "name": "ADH-AES128-SHA256"
              },
              {
                "anonymous": "True",
                "connectionStatus": "TLS / No ciphers available",
                "name": "ADH-AES256-GCM-SHA384"
              },
              {
                "anonymous": "True",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ADH-AES256-SHA"
              },
              {
                "anonymous": "True",
                "connectionStatus": "TLS / No ciphers available",
                "name": "ADH-AES256-SHA256"
              },
              {
                "anonymous": "True",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ADH-CAMELLIA128-SHA"
              },
              {
                "anonymous": "True",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ADH-CAMELLIA256-SHA"
              },
              {
                "anonymous": "True",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ADH-DES-CBC-SHA"
              },
              {
                "anonymous": "True",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ADH-DES-CBC3-SHA"
              },
              {
                "anonymous": "True",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ADH-RC4-MD5"
              },
              {
                "anonymous": "True",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ADH-SEED-SHA"
              },
              {
                "anonymous": "True",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "AECDH-AES128-SHA"
              },
              {
                "anonymous": "True",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "AECDH-AES256-SHA"
              },
              {
                "anonymous": "True",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "AECDH-DES-CBC3-SHA"
              },
              {
                "anonymous": "True",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "AECDH-NULL-SHA"
              },
              {
                "anonymous": "True",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "AECDH-RC4-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "AES128-GCM-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "AES128-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "AES256-GCM-SHA384"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "AES256-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "CAMELLIA128-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "CAMELLIA256-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DES-CBC-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "DH-DSS-AES128-GCM-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DH-DSS-AES128-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "DH-DSS-AES128-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "DH-DSS-AES256-GCM-SHA384"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DH-DSS-AES256-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "DH-DSS-AES256-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DH-DSS-CAMELLIA128-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DH-DSS-CAMELLIA256-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DH-DSS-DES-CBC-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DH-DSS-DES-CBC3-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DH-DSS-SEED-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "DH-RSA-AES128-GCM-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DH-RSA-AES128-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "DH-RSA-AES128-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "DH-RSA-AES256-GCM-SHA384"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DH-RSA-AES256-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "DH-RSA-AES256-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DH-RSA-CAMELLIA128-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DH-RSA-CAMELLIA256-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DH-RSA-DES-CBC-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DH-RSA-DES-CBC3-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DH-RSA-SEED-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "DHE-DSS-AES128-GCM-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DHE-DSS-AES128-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "DHE-DSS-AES128-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "DHE-DSS-AES256-GCM-SHA384"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DHE-DSS-AES256-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "DHE-DSS-AES256-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DHE-DSS-CAMELLIA128-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DHE-DSS-CAMELLIA256-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DHE-DSS-SEED-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "DHE-RSA-AES128-GCM-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DHE-RSA-AES128-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "DHE-RSA-AES128-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "DHE-RSA-AES256-GCM-SHA384"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DHE-RSA-AES256-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "DHE-RSA-AES256-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DHE-RSA-CAMELLIA128-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DHE-RSA-CAMELLIA256-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DHE-RSA-SEED-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "ECDH-ECDSA-AES128-GCM-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ECDH-ECDSA-AES128-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "ECDH-ECDSA-AES128-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "ECDH-ECDSA-AES256-GCM-SHA384"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ECDH-ECDSA-AES256-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "ECDH-ECDSA-AES256-SHA384"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ECDH-ECDSA-DES-CBC3-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ECDH-ECDSA-NULL-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ECDH-ECDSA-RC4-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "ECDH-RSA-AES128-GCM-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ECDH-RSA-AES128-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "ECDH-RSA-AES128-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "ECDH-RSA-AES256-GCM-SHA384"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ECDH-RSA-AES256-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "ECDH-RSA-AES256-SHA384"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ECDH-RSA-DES-CBC3-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ECDH-RSA-NULL-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ECDH-RSA-RC4-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "ECDHE-ECDSA-AES128-GCM-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ECDHE-ECDSA-AES128-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "ECDHE-ECDSA-AES128-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "ECDHE-ECDSA-AES256-GCM-SHA384"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ECDHE-ECDSA-AES256-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "ECDHE-ECDSA-AES256-SHA384"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ECDHE-ECDSA-DES-CBC3-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ECDHE-ECDSA-NULL-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ECDHE-ECDSA-RC4-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "ECDHE-RSA-AES128-GCM-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "ECDHE-RSA-AES128-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "ECDHE-RSA-AES256-GCM-SHA384"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "ECDHE-RSA-AES256-SHA384"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ECDHE-RSA-DES-CBC3-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ECDHE-RSA-NULL-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "EDH-DSS-DES-CBC-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "EDH-DSS-DES-CBC3-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "EDH-RSA-DES-CBC-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "EDH-RSA-DES-CBC3-SHA"
              },
              {
                "anonymous": "True",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "EXP-ADH-DES-CBC-SHA"
              },
              {
                "anonymous": "True",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "EXP-ADH-RC4-MD5"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "EXP-DES-CBC-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "EXP-EDH-DSS-DES-CBC-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "EXP-EDH-RSA-DES-CBC-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "EXP-RC2-CBC-MD5"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "EXP-RC4-MD5"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "IDEA-CBC-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "NULL-MD5"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "NULL-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "NULL-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "PSK-3DES-EDE-CBC-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "PSK-AES128-CBC-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "PSK-AES256-CBC-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "PSK-RC4-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "SEED-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "SRP-3DES-EDE-CBC-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "SRP-AES-128-CBC-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "SRP-AES-256-CBC-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "SRP-DSS-3DES-EDE-CBC-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "SRP-DSS-AES-128-CBC-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "SRP-DSS-AES-256-CBC-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "SRP-RSA-3DES-EDE-CBC-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "SRP-RSA-AES-128-CBC-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "SRP-RSA-AES-256-CBC-SHA"
              }
            ]
          }
        ],
        "acceptedCipherSuites": [
          {
            "cipherSuite": [
              {
                "anonymous": "False",
                "connectionStatus": "250 2.0.0 OK v191sm2428856wmd.24 - gsmtp",
                "keySize": "128",
                "name": "AES128-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "250 2.0.0 OK l1sm2443547wmg.21 - gsmtp",
                "keySize": "256",
                "name": "AES256-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "250 2.0.0 OK 200sm2471386wms.7 - gsmtp",
                "keySize": "112",
                "name": "DES-CBC3-SHA"
              },
              {
                "keyExchange": [
                  {
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
                  }
                ],
                "anonymous": "False",
                "connectionStatus": "250 2.0.0 OK vr10sm6599139wjc.38 - gsmtp",
                "keySize": "128",
                "name": "ECDHE-RSA-AES128-SHA"
              },
              {
                "keyExchange": [
                  {
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
                  }
                ],
                "anonymous": "False",
                "connectionStatus": "250 2.0.0 OK w9sm6620064wjf.20 - gsmtp",
                "keySize": "256",
                "name": "ECDHE-RSA-AES256-SHA"
              },
              {
                "keyExchange": [
                  {
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
                  }
                ],
                "anonymous": "False",
                "connectionStatus": "250 2.0.0 OK it4sm6651786wjb.0 - gsmtp",
                "keySize": "128",
                "name": "ECDHE-RSA-RC4-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "250 2.0.0 OK it4sm6651790wjb.0 - gsmtp",
                "keySize": "128",
                "name": "RC4-MD5"
              },
              {
                "anonymous": "False",
                "connectionStatus": "250 2.0.0 OK d81sm2454448wma.16 - gsmtp",
                "keySize": "128",
                "name": "RC4-SHA"
              }
            ]
          }
        ],
        "preferredCipherSuite": [
          {
            "cipherSuite": [
              {
                "keyExchange": [
                  {
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
                  }
                ],
                "anonymous": "False",
                "connectionStatus": "250 2.0.0 OK ee5sm6635600wjd.17 - gsmtp",
                "keySize": "128",
                "name": "ECDHE-RSA-RC4-SHA"
              }
            ]
          }
        ],
        "isProtocolSupported": "True",
        "title": "TLSV1 Cipher Suites"
      }
    ],
    "tlsv1_1": [
      {
        "errors": [
          ""
        ],
        "rejectedCipherSuites": [
          {
            "cipherSuite": [
              {
                "anonymous": "True",
                "connectionStatus": "TLS / No ciphers available",
                "name": "ADH-AES128-GCM-SHA256"
              },
              {
                "anonymous": "True",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ADH-AES128-SHA"
              },
              {
                "anonymous": "True",
                "connectionStatus": "TLS / No ciphers available",
                "name": "ADH-AES128-SHA256"
              },
              {
                "anonymous": "True",
                "connectionStatus": "TLS / No ciphers available",
                "name": "ADH-AES256-GCM-SHA384"
              },
              {
                "anonymous": "True",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ADH-AES256-SHA"
              },
              {
                "anonymous": "True",
                "connectionStatus": "TLS / No ciphers available",
                "name": "ADH-AES256-SHA256"
              },
              {
                "anonymous": "True",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ADH-CAMELLIA128-SHA"
              },
              {
                "anonymous": "True",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ADH-CAMELLIA256-SHA"
              },
              {
                "anonymous": "True",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ADH-DES-CBC-SHA"
              },
              {
                "anonymous": "True",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ADH-DES-CBC3-SHA"
              },
              {
                "anonymous": "True",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ADH-RC4-MD5"
              },
              {
                "anonymous": "True",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ADH-SEED-SHA"
              },
              {
                "anonymous": "True",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "AECDH-AES128-SHA"
              },
              {
                "anonymous": "True",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "AECDH-AES256-SHA"
              },
              {
                "anonymous": "True",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "AECDH-DES-CBC3-SHA"
              },
              {
                "anonymous": "True",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "AECDH-NULL-SHA"
              },
              {
                "anonymous": "True",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "AECDH-RC4-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "AES128-GCM-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "AES128-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "AES256-GCM-SHA384"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "AES256-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "CAMELLIA128-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "CAMELLIA256-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DES-CBC-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "DH-DSS-AES128-GCM-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DH-DSS-AES128-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "DH-DSS-AES128-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "DH-DSS-AES256-GCM-SHA384"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DH-DSS-AES256-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "DH-DSS-AES256-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DH-DSS-CAMELLIA128-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DH-DSS-CAMELLIA256-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DH-DSS-DES-CBC-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DH-DSS-DES-CBC3-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DH-DSS-SEED-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "DH-RSA-AES128-GCM-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DH-RSA-AES128-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "DH-RSA-AES128-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "DH-RSA-AES256-GCM-SHA384"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DH-RSA-AES256-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "DH-RSA-AES256-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DH-RSA-CAMELLIA128-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DH-RSA-CAMELLIA256-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DH-RSA-DES-CBC-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DH-RSA-DES-CBC3-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DH-RSA-SEED-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "DHE-DSS-AES128-GCM-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DHE-DSS-AES128-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "DHE-DSS-AES128-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "DHE-DSS-AES256-GCM-SHA384"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DHE-DSS-AES256-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "DHE-DSS-AES256-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DHE-DSS-CAMELLIA128-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DHE-DSS-CAMELLIA256-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DHE-DSS-SEED-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "DHE-RSA-AES128-GCM-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DHE-RSA-AES128-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "DHE-RSA-AES128-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "DHE-RSA-AES256-GCM-SHA384"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DHE-RSA-AES256-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "DHE-RSA-AES256-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DHE-RSA-CAMELLIA128-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DHE-RSA-CAMELLIA256-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DHE-RSA-SEED-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "ECDH-ECDSA-AES128-GCM-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ECDH-ECDSA-AES128-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "ECDH-ECDSA-AES128-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "ECDH-ECDSA-AES256-GCM-SHA384"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ECDH-ECDSA-AES256-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "ECDH-ECDSA-AES256-SHA384"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ECDH-ECDSA-DES-CBC3-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ECDH-ECDSA-NULL-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ECDH-ECDSA-RC4-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "ECDH-RSA-AES128-GCM-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ECDH-RSA-AES128-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "ECDH-RSA-AES128-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "ECDH-RSA-AES256-GCM-SHA384"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ECDH-RSA-AES256-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "ECDH-RSA-AES256-SHA384"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ECDH-RSA-DES-CBC3-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ECDH-RSA-NULL-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ECDH-RSA-RC4-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "ECDHE-ECDSA-AES128-GCM-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ECDHE-ECDSA-AES128-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "ECDHE-ECDSA-AES128-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "ECDHE-ECDSA-AES256-GCM-SHA384"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ECDHE-ECDSA-AES256-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "ECDHE-ECDSA-AES256-SHA384"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ECDHE-ECDSA-DES-CBC3-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ECDHE-ECDSA-NULL-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ECDHE-ECDSA-RC4-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "ECDHE-RSA-AES128-GCM-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "ECDHE-RSA-AES128-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "ECDHE-RSA-AES256-GCM-SHA384"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "ECDHE-RSA-AES256-SHA384"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ECDHE-RSA-DES-CBC3-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ECDHE-RSA-NULL-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "EDH-DSS-DES-CBC-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "EDH-DSS-DES-CBC3-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "EDH-RSA-DES-CBC-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "EDH-RSA-DES-CBC3-SHA"
              },
              {
                "anonymous": "True",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "EXP-ADH-DES-CBC-SHA"
              },
              {
                "anonymous": "True",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "EXP-ADH-RC4-MD5"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "EXP-DES-CBC-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "EXP-EDH-DSS-DES-CBC-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "EXP-EDH-RSA-DES-CBC-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "EXP-RC2-CBC-MD5"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "EXP-RC4-MD5"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "IDEA-CBC-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "NULL-MD5"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "NULL-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "NULL-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "PSK-3DES-EDE-CBC-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "PSK-AES128-CBC-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "PSK-AES256-CBC-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "PSK-RC4-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "SEED-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "SRP-3DES-EDE-CBC-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "SRP-AES-128-CBC-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "SRP-AES-256-CBC-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "SRP-DSS-3DES-EDE-CBC-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "SRP-DSS-AES-128-CBC-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "SRP-DSS-AES-256-CBC-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "SRP-RSA-3DES-EDE-CBC-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "SRP-RSA-AES-128-CBC-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "SRP-RSA-AES-256-CBC-SHA"
              }
            ]
          }
        ],
        "acceptedCipherSuites": [
          {
            "cipherSuite": [
              {
                "anonymous": "False",
                "connectionStatus": "250 2.0.0 OK r13sm2464217wmg.12 - gsmtp",
                "keySize": "128",
                "name": "AES128-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "250 2.0.0 OK q141sm2479845wmg.3 - gsmtp",
                "keySize": "256",
                "name": "AES256-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "250 2.0.0 OK w66sm2466821wme.11 - gsmtp",
                "keySize": "112",
                "name": "DES-CBC3-SHA"
              },
              {
                "keyExchange": [
                  {
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
                  }
                ],
                "anonymous": "False",
                "connectionStatus": "250 2.0.0 OK 199sm2430311wml.22 - gsmtp",
                "keySize": "128",
                "name": "ECDHE-RSA-AES128-SHA"
              },
              {
                "keyExchange": [
                  {
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
                  }
                ],
                "anonymous": "False",
                "connectionStatus": "250 2.0.0 OK l186sm2434187wmg.19 - gsmtp",
                "keySize": "256",
                "name": "ECDHE-RSA-AES256-SHA"
              },
              {
                "keyExchange": [
                  {
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
                  }
                ],
                "anonymous": "False",
                "connectionStatus": "250 2.0.0 OK l1sm6637724wjx.13 - gsmtp",
                "keySize": "128",
                "name": "ECDHE-RSA-RC4-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "250 2.0.0 OK s127sm2472299wmb.8 - gsmtp",
                "keySize": "128",
                "name": "RC4-MD5"
              },
              {
                "anonymous": "False",
                "connectionStatus": "250 2.0.0 OK r65sm2436440wmb.20 - gsmtp",
                "keySize": "128",
                "name": "RC4-SHA"
              }
            ]
          }
        ],
        "preferredCipherSuite": [
          {
            "cipherSuite": [
              {
                "keyExchange": [
                  {
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
                  }
                ],
                "anonymous": "False",
                "connectionStatus": "250 2.0.0 OK wx10sm6599935wjb.40 - gsmtp",
                "keySize": "128",
                "name": "ECDHE-RSA-RC4-SHA"
              }
            ]
          }
        ],
        "isProtocolSupported": "True",
        "title": "TLSV1_1 Cipher Suites"
      }
    ],
    "tlsv1_2": [
      {
        "errors": [
          ""
        ],
        "rejectedCipherSuites": [
          {
            "cipherSuite": [
              {
                "anonymous": "True",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ADH-AES128-GCM-SHA256"
              },
              {
                "anonymous": "True",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ADH-AES128-SHA"
              },
              {
                "anonymous": "True",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ADH-AES128-SHA256"
              },
              {
                "anonymous": "True",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ADH-AES256-GCM-SHA384"
              },
              {
                "anonymous": "True",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ADH-AES256-SHA"
              },
              {
                "anonymous": "True",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ADH-AES256-SHA256"
              },
              {
                "anonymous": "True",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ADH-CAMELLIA128-SHA"
              },
              {
                "anonymous": "True",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ADH-CAMELLIA256-SHA"
              },
              {
                "anonymous": "True",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ADH-DES-CBC-SHA"
              },
              {
                "anonymous": "True",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ADH-DES-CBC3-SHA"
              },
              {
                "anonymous": "True",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ADH-RC4-MD5"
              },
              {
                "anonymous": "True",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ADH-SEED-SHA"
              },
              {
                "anonymous": "True",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "AECDH-AES128-SHA"
              },
              {
                "anonymous": "True",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "AECDH-AES256-SHA"
              },
              {
                "anonymous": "True",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "AECDH-DES-CBC3-SHA"
              },
              {
                "anonymous": "True",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "AECDH-NULL-SHA"
              },
              {
                "anonymous": "True",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "AECDH-RC4-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "AES128-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "AES256-GCM-SHA384"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "AES256-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "CAMELLIA128-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "CAMELLIA256-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DES-CBC-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DH-DSS-AES128-GCM-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DH-DSS-AES128-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DH-DSS-AES128-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DH-DSS-AES256-GCM-SHA384"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DH-DSS-AES256-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DH-DSS-AES256-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DH-DSS-CAMELLIA128-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DH-DSS-CAMELLIA256-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DH-DSS-DES-CBC-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DH-DSS-DES-CBC3-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DH-DSS-SEED-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DH-RSA-AES128-GCM-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DH-RSA-AES128-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DH-RSA-AES128-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DH-RSA-AES256-GCM-SHA384"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DH-RSA-AES256-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DH-RSA-AES256-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DH-RSA-CAMELLIA128-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DH-RSA-CAMELLIA256-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DH-RSA-DES-CBC-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DH-RSA-DES-CBC3-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DH-RSA-SEED-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DHE-DSS-AES128-GCM-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DHE-DSS-AES128-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DHE-DSS-AES128-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DHE-DSS-AES256-GCM-SHA384"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DHE-DSS-AES256-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DHE-DSS-AES256-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DHE-DSS-CAMELLIA128-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DHE-DSS-CAMELLIA256-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DHE-DSS-SEED-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DHE-RSA-AES128-GCM-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DHE-RSA-AES128-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DHE-RSA-AES128-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DHE-RSA-AES256-GCM-SHA384"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DHE-RSA-AES256-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DHE-RSA-AES256-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DHE-RSA-CAMELLIA128-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DHE-RSA-CAMELLIA256-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "DHE-RSA-SEED-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ECDH-ECDSA-AES128-GCM-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ECDH-ECDSA-AES128-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ECDH-ECDSA-AES128-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ECDH-ECDSA-AES256-GCM-SHA384"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ECDH-ECDSA-AES256-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ECDH-ECDSA-AES256-SHA384"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ECDH-ECDSA-DES-CBC3-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ECDH-ECDSA-NULL-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ECDH-ECDSA-RC4-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ECDH-RSA-AES128-GCM-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ECDH-RSA-AES128-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ECDH-RSA-AES128-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ECDH-RSA-AES256-GCM-SHA384"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ECDH-RSA-AES256-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ECDH-RSA-AES256-SHA384"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ECDH-RSA-DES-CBC3-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ECDH-RSA-NULL-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ECDH-RSA-RC4-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ECDHE-ECDSA-AES128-GCM-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ECDHE-ECDSA-AES128-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ECDHE-ECDSA-AES128-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ECDHE-ECDSA-AES256-GCM-SHA384"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ECDHE-ECDSA-AES256-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ECDHE-ECDSA-AES256-SHA384"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ECDHE-ECDSA-DES-CBC3-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ECDHE-ECDSA-NULL-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ECDHE-ECDSA-RC4-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ECDHE-RSA-AES128-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ECDHE-RSA-AES256-GCM-SHA384"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ECDHE-RSA-AES256-SHA384"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ECDHE-RSA-DES-CBC3-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "ECDHE-RSA-NULL-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "EDH-DSS-DES-CBC-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "EDH-DSS-DES-CBC3-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "EDH-RSA-DES-CBC-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "EDH-RSA-DES-CBC3-SHA"
              },
              {
                "anonymous": "True",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "EXP-ADH-DES-CBC-SHA"
              },
              {
                "anonymous": "True",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "EXP-ADH-RC4-MD5"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "EXP-DES-CBC-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "EXP-EDH-DSS-DES-CBC-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "EXP-EDH-RSA-DES-CBC-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "EXP-RC2-CBC-MD5"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "EXP-RC4-MD5"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "IDEA-CBC-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "NULL-MD5"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "NULL-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "NULL-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "PSK-3DES-EDE-CBC-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "PSK-AES128-CBC-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "PSK-AES256-CBC-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "PSK-RC4-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / Alert handshake failure",
                "name": "SEED-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "SRP-3DES-EDE-CBC-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "SRP-AES-128-CBC-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "SRP-AES-256-CBC-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "SRP-DSS-3DES-EDE-CBC-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "SRP-DSS-AES-128-CBC-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "SRP-DSS-AES-256-CBC-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "SRP-RSA-3DES-EDE-CBC-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "SRP-RSA-AES-128-CBC-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "TLS / No ciphers available",
                "name": "SRP-RSA-AES-256-CBC-SHA"
              }
            ]
          }
        ],
        "acceptedCipherSuites": [
          {
            "cipherSuite": [
              {
                "anonymous": "False",
                "connectionStatus": "250 2.0.0 OK 77sm2447364wml.20 - gsmtp",
                "keySize": "128",
                "name": "AES128-GCM-SHA256"
              },
              {
                "anonymous": "False",
                "connectionStatus": "250 2.0.0 OK w9sm6619816wjf.20 - gsmtp",
                "keySize": "128",
                "name": "AES128-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "250 2.0.0 OK w66sm2466575wme.11 - gsmtp",
                "keySize": "256",
                "name": "AES256-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "250 2.0.0 OK b134sm2455568wmf.9 - gsmtp",
                "keySize": "112",
                "name": "DES-CBC3-SHA"
              },
              {
                "keyExchange": [
                  {
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
                  }
                ],
                "anonymous": "False",
                "connectionStatus": "250 2.0.0 OK it4sm6651383wjb.0 - gsmtp",
                "keySize": "128",
                "name": "ECDHE-RSA-AES128-GCM-SHA256"
              },
              {
                "keyExchange": [
                  {
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
                  }
                ],
                "anonymous": "False",
                "connectionStatus": "250 2.0.0 OK t126sm2438288wmd.23 - gsmtp",
                "keySize": "128",
                "name": "ECDHE-RSA-AES128-SHA"
              },
              {
                "keyExchange": [
                  {
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
                  }
                ],
                "anonymous": "False",
                "connectionStatus": "250 2.0.0 OK lf10sm6618966wjb.23 - gsmtp",
                "keySize": "256",
                "name": "ECDHE-RSA-AES256-SHA"
              },
              {
                "keyExchange": [
                  {
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
                  }
                ],
                "anonymous": "False",
                "connectionStatus": "250 2.0.0 OK e63sm2461858wma.7 - gsmtp",
                "keySize": "128",
                "name": "ECDHE-RSA-RC4-SHA"
              },
              {
                "anonymous": "False",
                "connectionStatus": "250 2.0.0 OK j4sm2451239wmg.18 - gsmtp",
                "keySize": "128",
                "name": "RC4-MD5"
              },
              {
                "anonymous": "False",
                "connectionStatus": "250 2.0.0 OK l5sm6632491wjf.11 - gsmtp",
                "keySize": "128",
                "name": "RC4-SHA"
              }
            ]
          }
        ],
        "preferredCipherSuite": [
          {
            "cipherSuite": [
              {
                "keyExchange": [
                  {
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
                  }
                ],
                "anonymous": "False",
                "connectionStatus": "250 2.0.0 OK c67sm2453246wmh.11 - gsmtp",
                "keySize": "128",
                "name": "ECDHE-RSA-AES128-GCM-SHA256"
              }
            ]
          }
        ],
        "isProtocolSupported": "True",
        "title": "TLSV1_2 Cipher Suites"
      }
    ]
  }
}
```
