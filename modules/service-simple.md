# Service Simple

The Service grabber tries to extract product specific information from a remote address. This module is much faster than "service", since it returns less information. If you want more details, including for example header information, please use the [service module](https://github.com/binaryedge/api-publicdoc/blob/master/modules/service.md "service")

This modules provides the following data:

  * name: Type of service
  * product: Product designation
  * version: Version
  * cpe: Common Platform Enumeration, if available


### Service Simple Request Example

  ```
curl -v -L https://api.binaryedge.io/v1/tasks  -d  '{"type":"scan", "options":[{"targets":["149.202.178.130"], "ports":[{"port":80,"protocol":"tcp","modules": ["service-simple"]}]}]}' -H 'X-Token:NNNNNN'
  ```

### Service Simple Event Example
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
				"product": "nginx",
				"name": "http",
				"extrainfo": "Ubuntu",
				"cpe": ["cpe:/a:igor_sysoev:nginx:1.4.6", "cpe:/o:canonical:ubuntu_linux", "cpe:/o:linux:linux_kernel"],
				"version": "1.4.6",
				"ostype": "Linux",
				"method": "probe_matching"
			}
		}
	}
}
```
