# Telnet

Grab Telnet information.

## Telnet Request Example

```
curl -v -L https://api.binaryedge.io/v1/tasks -d '{"type":"scan", "options":[{"targets":["X.X.X.X"], "ports":[{"port":23, "protocol":"tcp", "modules":["telnet"]}]}]}' -H "X-Token:<Token>"
```

## Schema

### Telnet Event Schema

```json
{
  ...
  "result": {
    "data": {
      "banner": "string",
      "will": [{
          "name": "string",
          "value": "int"
        }],
      "do": [{
          "name": "string",
          "value": "int"
        }],
      "wont": [{
          "name": "string",
          "value": "int"
        }],
      "dont": [{
          "name": "string",
          "value": "int"
        }]
    }
  }
}
```

### Contents of the fields:

  * banner - Service banner.
  * will - Indicates the desire to begin performing, or confirmation that you are now performing, the indicated option.
  * do - Indicates the request that the other party perform, or confirmation that you are expecting the other party to perform, the indicated option.
  * wont - Indicates the refusal to perform, or continue performing, the indicated option.
  * dont - Indicates the demand that the other party stop performing, or confirmation that you are no longer expecting the other party to perform, the indicated option.

More information at: https://tools.ietf.org/html/rfc854

## Telnet Event Example

```json
{
  "origin": {
    "type": "telnet",
    "job_id": "client-26069164-abe3-4eb4-a65a-e1f524ef0906",
    "client_id": "client",
    "module": "grabber",
    "country": "de",
    "ts": 1464874685429
  },
  "target": {
    "ip": "X.X.X.X",
    "port": "23"
  },
  "result": {
    "data": {
      "telnet": {
        "banner": "\r\n\r\nNetwork OS (swf1)\r\n4.1.3\r\n\r\nswf1 login: ",
        "will": [
          {
            "name": "Suppress Go Ahead",
            "value": 3
          },
          {
            "name": "Status",
            "value": 5
          },
          {
            "name": "Suppress Go Ahead",
            "value": 3
          },
          {
            "name": "Echo",
            "value": 1
          }
        ],
        "do": [
          {
            "name": "Terminal Type",
            "value": 24
          },
          {
            "name": "Terminal Speed",
            "value": 32
          },
          {
            "name": "X Display Location",
            "value": 35
          },
          {
            "name": "New Environment Option",
            "value": 39
          },
          {
            "name": "Echo",
            "value": 1
          },
          {
            "name": "Negotiate About Window Size",
            "value": 31
          },
          {
            "name": "Remote Flow Control",
            "value": 33
          }
        ]
      }
    }
  }
}
```
