# Service Simple

The Service Simple grabber tries to extract product specific information from service running on a remote address. This module is much faster than "service", since it returns less information. If you want more details, including header information for example, please use the [service module](https://github.com/binaryedge/api-publicdoc/blob/master/modules/service.md "service")

This module provides the following data (if available):

* **state**: Information regarding the state of the connection to the target
  * **state**: State if the connection to the target. Possible values for this field are:
    * **open**: The connection was established, data was sent and the target returned any response
    * **open|filtered**: The connection was established, data was sent, but the target did not respond
    * **closed**: The connection was not established.

* **service**: Information regarding the service that is likely to be running on the target
  * **name**: Type of service that is running
  * **product**: Product designation (and Vendor)
  * **version**: Application version number
  * **device**: Type of device running the service
  * **ostype**: Operating system running the service
  * **hostname**: Hostname (if any) offered by the service
  * **extrainfo**: Extra information extracted, can be an OS, version of a framework, etc
  * **cpe**: List of Common Platform Enumeration tags, if available
  * **banner**: Server response from which information was extracted
  * **method**: Method used to match or extract information from server responses. Possible values for this field are:
	* **probe_matching**: Server responses matched one of the expected responses for the probes that were sent
	* **probe_extraction**: Customized information extraction, used when server responses do not match expected responses, but have relevant information
	* **probe_matching/probe_extraction**: It's a mix of the previous methods, used when simple matching with expected responses does not return sufficient information
	* **table_default**: No information was obtained, hence the resulting service name is simply a speculation given the port number

### Service Simple Request Example

  ```
curl -v -L https://api.binaryedge.io/v1/tasks  -d  '{"type":"scan", "options":[{"targets":["149.202.178.130"], "ports":[{"port":80,"protocol":"tcp","modules": ["service-simple"]}]}]}' -H "X-Token:NNNNNN"
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
