# MQTT (beta)

Grab MQTT information, including messages and topics.

This module connects to MQTT brokers and grabs data it. The module listens for **30 seconds** for the first **100 messages** until a maximum of **9 MB** of data if received. 

More information about MQTT at http://mqtt.org/documentation .

## MQTT Request Example

```
curl -v -L https://api.binaryedge.io/v1/tasks -d '{"type":"scan", "options":[{"targets":["X.X.X.X"], "ports":[{"port":1883, "protocol":"tcp", "modules":["mqtt"]}]}]}' -H "X-Token:<Token>"
```

## Schema

### MQTT Event Schema

```json
{
  ...
  "result": {
    "data": {
      "connected": "boolean",
      "auth": "boolean",
      "messages": ["string"],
      "topics": ["string"],
      "num_events": "int",
      "num_topics": "int",
      "bytes_captured": "int",
      "connack": {...}
    }
}
```

### Contents of the fields:

  * connected - True if was able to connect
  * auth - Auth enabled?
  * messages - Collected Messages
  * topics - Topics found
  * num_events - Number of seen events
  * num_topics - Number of seen topics
  * bytes_captured - Bytes captured
  * connack - MQTT Connack packet (http://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html#_Toc398718033)

## MQTT Event Example

```json
{
    "origin": {
        "type": "mqtt",
        "job_id": "client-3cee033d-981b-456d-a859-83d54f2ezb21",
        "client_id": "tiago",
        "module": "grabber",
        "country": "uk",
        "ts": 1472051982661
    },
    "target": {
        "ip": "XXX.XXX.XXX.XXX",
        "port": 1883
    },
    "result": {
        "data": {
            "connected": true,
            "auth": false,
            "messages": [{
                "topic": "/",
                "msg": "Hello world!"
            }, {
                "topic": "/kk",
                "msg": "test"
            },
            ...
            ],
            "connack": {
                "cmd": "connack",
                "retain": false,
                "qos": 0,
                "dup": false,
                "length": 2,
                "topic": null,
                "payload": null,
                "sessionPresent": false,
                "returnCode": 0
            },
            "num_events": 100,
            "num_topics": 100,
            "bytes_captured": 35208,
            "topics": ["/", "/kk",...]
        }
    }
}
```
