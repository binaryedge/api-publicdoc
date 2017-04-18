# Service

The Service grabber tries to extract product specific information from a remote address. If you just want product name and version, consider using the faster [service-simple module](https://github.com/binaryedge/api-publicdoc/blob/master/modules/service-simple.md "service")

## Service Request Example

```
curl -v -L https://api.binaryedge.io/v1/tasks -d '{"type":"scan", "options":[{"targets":["X.X.X.X"], "ports":[{"port":80, "protocol":"tcp", "modules":["service"], "config":{}}]}]}' -H "X-Token:<Token>"
```

### Service Request Options

These are optional parameters that can alter the behaviour of the module. These options can be inserted into the "config" object on the request.

  * user_agent - Change HTTP User Agent.
    * "config":{"user_agent":"Test user Agent"}

## Schema

### Service Simple Event Schema

```json
 {
    ...
    "result": {
        "data": {
            "service": {
                "name": "string",
                "product": "string",
                "version": "string",
                "device": "string",
                "ostype": "string",
                "hostname": "string",
                "extrainfo": "string",
                "cpe": ["string"], 
            },
            "scripts": [
                {"results": ["string"],
                 "id": "string",
                 "output": "string"}
            ]
        }
    }
}
```

### Contents of the fields

This module provides the following data (if available):

* **service**: Information regarding the service that is likely to be running on the target
  * **name**: Type of service that is running
  * **product**: Product designation (and Vendor)
  * **version**: Application version number
  * **device**: Type of device running the service
  * **ostype**: Operating system running the service
  * **hostname**: Hostname (if any) offered by the service
  * **extrainfo**: Extra information extracted, can be an OS, version of a framework, etc
  * **cpe**: List of Common Platform Enumeration tags, if available
* **scripts**: Extra information obtained by a set os scripts (results vary with the service found)
  * **results**: Formatted output of the script
  * **id**: Identifier of the script that generated the information
  * **output**: Raw output of the script

## Service Event Example

```json
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
    "result": {
        "data": {
            "service": {
                "name": "http",
                "product": "nginx",
                "version": "1.4.6",
                "extrainfo": "Ubuntu",
                "ostype": "Linux",
                "cpe": ["cpe:/a:igor_sysoev:nginx:1.4.6", "cpe:/o:linux:linux_kernel"]
            },
            "scripts": [
                {"results": ["GET", "HEAD"],
                 "id": "http-methods",
                 "output": "\n  Supported Methods: GET HEAD"},
                {"results": ["nginx/1.4.6 (Ubuntu)"],
                 "id": "http-server-header",
                 "output": "nginx/1.4.6 (Ubuntu)"},
            ]
        }
    }
}
```
