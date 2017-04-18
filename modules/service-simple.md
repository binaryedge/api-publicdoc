# Service Simple

The Service Simple grabber tries to extract product specific information from service running on a remote address. This module is much faster than "service", since it returns less information. If you want more details, including header information for example, please use the [service module](https://github.com/binaryedge/api-publicdoc/blob/master/modules/service.md "service")

## Service Simple Request Example

```
curl -v -L https://api.binaryedge.io/v1/tasks -d '{"type":"scan", "options":[{"targets":["X.X.X.X"], "ports":[{"port":80, "protocol":"tcp", "modules":["service-simple"]}]}]}' -H "X-Token:<Token>"
```

### Service Simple Request Options

These are optional parameters that can alter the behaviour of the module. These options can be inserted into the "config" object on the request.

  * prioritize_probes - List of probe names to prioritize
    * "config":{"prioritize_probes":"SIPOptions, GetRequest, SSLSessionReq, NULL, HTTPOptions, RTSPRequest"}
  * custom_probes - List of custom probes to use
    * "config":{"custom_probes":"GET / HTTP/1.0\r\n\r\n,OPTIONS / HTTP/1.0\r\n\r\n"}
  * probe_rarity - Rarity level of probes used (light/probable/default/all)
    * "config":{"probe_rarity":"all"}

## Schema

### Service Simple Event Schema

```json
{
    ...
    "result": {
        "data": {
          "state": {
            "state": "string"
          },
          "service": {
              "name": "string",
              "product": "string",
              "version": "string",
              "device": "string",
              "ostype": "string",
              "hostname": "string",
              "extrainfo": "string",
              "cpe": ["string"],
              "banner": "string",
              "method": "string"
          }
        }
    }
}
```

### Contents of the fields

This module provides the following data (if available):

* **state**: Information regarding the state of the connection to the target
  * **state**: State of the connection to the target. Possible values for this field are:
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

## Service Simple Event Example

```json
{  
  ...
  "result":{  
    "data":{  
      "state":{  
        "state":"open"
      },
      "service":{  
        "product":"nginx",
        "name":"http",
        "extrainfo":"Ubuntu",
        "cpe":[  
          "cpe:/a:igor_sysoev:nginx:1.4.6",
          "cpe:/o:canonical:ubuntu_linux",
          "cpe:/o:linux:linux_kernel"
        ],
        "state":"open",
        "version":"1.4.6",
        "ostype":"Linux",
        "banner":"\"HTTP/1.1 200 OK\\\\r\\\\nServer: nginx/1.4.6 (Ubuntu)\\\\r\\\\nDate: Tue, 18 Apr 2017 09:39:42 GMT\\\\r\\\\nContent-Type: text/html\\\\r\\\\nContent-Length: 612\\\\r\\\\nLast-Modified: Tue, 04 Mar 2014 11:46:45 GMT\\\\r\\\\nConnection: close\\\\r\\\\nETag: \\\"5315bd25-264\\\"\\\\r\\\\nAccept-Ranges: bytes\\\\r\\\\n\\\\r\\\\n<!DOCTYPE html>\\\\n<html>\\\\n<head>\\\\n<title>Welcome to nginx!</title>\\\\n<style>\\\\n    body {\\\\n        width: 35em;\\\\n        margin: 0 auto;\\\\n        font-family: Tahoma, Verdana, Arial, sans-serif;\\\\n    }\\\\n</style>\\\\n</head>\\\\n<body>\\\\n<h1>Welcome to nginx!</h1>\\\\n<p>If you see this page, the nginx web server is successfully installed and\\\\nworking. Further configuration is required.</p>\\\\n\\\\n<p>For online documentation and support please refer to\\\\n<a href=\\\"http://nginx.org/\\\">nginx.org</a>.<br/>\\\\nCommercial support is available at\\\\n<a href=\\\"http://nginx.com/\\\">nginx.com</a>.</p>\\\\n\\\\n<p><em>Thank you for using nginx.</em></p>\\\\n</body>\\\\n</html>\\\\n\"",
        "method":"probe_matching"
      }
    }
  }
}
```
