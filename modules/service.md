# Service

The Service grabber tries to extract product specific information from a remote address. If you just want product name and version, consider using the faster [service-simple module](https://github.com/binaryedge/api-publicdoc/blob/master/modules/service-simple.md "service")

### Service Event Example
```
 {
    "origin": {
      "type": "service",
      "job_id": "client-816f1185-4bc1-4b5f-9a7d-61a2df315a6b",
      "client_id": "client",
      "country": "uk",
      "module": "grabber",
      "ts": 1453385574412
    },
    "target": {
      "ip": "X.X.X.X",
      "port": 80,
      "protocol": "tcp"
    },
    "result":
    {
        "data":
        {
            "service":
            {
                "name":"http",
                "product":"Apache httpd",
                "version":"2.2.15",
                "extrainfo":"(CentOS)",
                "cpe":["cpe:/a:apache:http_server:2.2.15"]
            },
            "script":
            [
                {
                    "id":"http-methods",
                    "output":"No Allow or Public header in OPTIONS response (status code 400)"
                },
                {
                    "id":"http-title",
                    "output":"Invalid URL",
                    scripts:
                    {
                    ....
                        <extra script information, dynamic, because it depends on the script>
                    ....
                    }
                }
            ]
        }
    }
}
```
