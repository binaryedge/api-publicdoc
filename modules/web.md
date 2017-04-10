# Web (BETA)

Extract Web technologies information and headers.

## Web Request Example

```
curl -v -L https://api.binaryedge.io/v1/tasks  -d  '{"type":"grab", "options":[{"targets":["X.X.X.X"], "ports":[{"port":80, "config":{}, "modules": ["web"]}]}]}' -H "X-Token:<Token>"
```

## Request Options

These are optional parameters that can alter the behaviour of the module. These options can be inserted into the "config" object on the request.

  * https: true - whether to use an HTTPS instead of HTTP

## Schema

### Web Event Schema

```json
{
  ...
  "result": {
    "data": {
      "apps": [{
          "name": "string",
          "confidence": "int",
          "version": "string",
          "categories": ["string"]
        }]
      },
      "headers": {
      	"string": "string"
        }
      }
    }
  }
}
```

### Contents of the fields:

  * apps - Request made by the module
  	* name - Name of the technoloy
  	* confidence - Confidence level for the match
    * version - Version of the technology
    * categories - Categories of the techonology
  * headers - Headers from the web server

## Web Event Example

```json
{
...
  "result": {
    "data": {
      "apps": [
        {
          "name": "Apache",
          "confidence": 100,
          "version": "2.2.26",
          "categories": [
            "web-servers"
          ]
        },
        {
          "name": "OpenSSL",
          "confidence": 100,
          "version": "0.9.8e",
          "categories": [
            "web-server-extensions"
          ]
        },
        {
          "name": "UNIX",
          "confidence": 100,
          "version": "",
          "categories": [
            "operating-systems"
          ]
        },
        {
          "name": "mod_ssl",
          "confidence": 100,
          "version": "2.2.26",
          "categories": [
            "web-server-extensions"
          ]
        }
      ],
      "headers": {
        "date": "Fri, 08 Jul 2016 16:40:05 GMT",
        "server": "Apache/2.2.26 (Unix) mod_ssl/2.2.26 OpenSSL/0.9.8e-fips-rhel5 mod_bwlimited/1.4",
        "last-modified": "Wed, 12 Feb 2014 07:42:45 GMT",
        "etag": "\"25de0f5-6f-4f230b7eda740\"",
        "accept-ranges": "bytes",
        "content-length": "111",
        "keep-alive": "timeout=5, max=100",
        "connection": "Keep-Alive",
        "content-type": "text/html"
      }
    }
  }
}
```
