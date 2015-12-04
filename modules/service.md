# Service

The Service grabber tries to extract product specific information from a remote address.

### Service Event Example
```
 {
  "result_type":"service",
    "provider":"min-29-12699-ustx-dev",
    "origin":"grabber",
    "src":{
        "ip":"xx.xxx.xx.x",
        "port":80,
        "protocol":"tcp"
    },
    "result":
    {
        "data":
        {
            "service":
            {
                "name":"http"
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
                        <extra script information, dynamic because if depends on the script>
                    ....
                    }
                }
            ]
        }
    },
    "ts":1446516004130
}
```
