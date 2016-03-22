# Service Simple

The Service grabber tries to extract product specific information from a remote address. This module is much faster than "service", since it returns less information. If you want more details, including for example header information, please use the [service module](https://github.com/binaryedge/api-publicdoc/blob/master/modules/service.md "service")

This modules provides the following data:

  * name: Type of service
  * product: Product designation
  * version: Version
  * cpe: Common Platform Enumeration, if available


### Service Event Example
```

{
	"origin": {
		"type": "service-simple",
		"job_id": "3bafd752-3ecc-4ba7-ae9a-f851025c3e50",
		"client_id": "client",
		"module": "grabber",
		"country": "us",
		"ts": 1458647916156
	},
	"target": {
		"ip": "X.X.X.X",
		"port": 80,
		"protocol": "tcp"
	},
	"result": {
    "data": {
      "service": {
  			"product": "Tornado httpd",
  			"version": "2.1.1git",
  			"cpe": ["cpe:/a:tornadoweb:tornado:2.1.1git"],
  			"name": "http"
      }
		}
	}
}
```
