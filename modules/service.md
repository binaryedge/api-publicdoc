# Service

The Service grabber tries to extract product specific information from a remote address. If you just want product name and version, consider using the faster [service-simple module](https://github.com/binaryedge/api-publicdoc/blob/master/modules/service-simple.md "service")

### Service Request Example

```
curl -v -L https://api.binaryedge.io/v1/tasks  -d  '{"type":"scan", "options":[{"targets":["149.202.178.130"], "ports":[{"port":80,"protocol":"tcp","modules": ["service"]}]}]}' -H 'X-Token:XXXXXX'
```

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
        				"name": "http",
        				"product": "nginx",
        				"version": "1.4.6",
        				"extrainfo": "Ubuntu",
        				"ostype": "Linux",
        				"cpe": ["cpe:/a:igor_sysoev:nginx:1.4.6", "cpe:/o:linux:linux_kernel"]
        			},
        		"scripts": [
              {
        				"results": ["GET", "HEAD"],
        				"id": "http-methods",
        				"output": "\n  Supported Methods: GET HEAD"
        			}, {
        				"results": ["nginx/1.4.6 (Ubuntu)"],
        				"id": "http-server-header",
        				"output": "nginx/1.4.6 (Ubuntu)"
        			},
              {
                  <extra scripts information, dynamic, depending on service detected>
              }
            ]
        }
    }
}
```
