# Json Output List:
Standart 443 SSL Scan

[ip]: string #ex: 63.254.217.20

[ipv6]: string #ex: 2a00:1450:400c:c04::6d

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
                        [int]: string #ex:[0] 00:a4:ba:38:27:0e:...

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
            errors: string #ex: 0
            failedAttempts: string #ex: 0
            isSupported: True/False 
            successfulAttempts: string #ex: 5
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
<*1> Same part for all openSSL Ciphers tests

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
