# MQTT (beta)

Grab MQTT information, messages and topics.

This module connects to MQTT brokers and grabs information. It will connected to a broker and listen for **30 seconds** for the first **100 messages** until a maximun of **9 MB** of data. 


More information about MQTT at http://mqtt.org/documentation .

## MQTT Request Example

  ```
curl -v -L https://api.binaryedge.io/v1/tasks  -d  '{"type":"grab", "options":[{"targets":["X.X.X.X"], "ports":[{"port":1883,"modules": ["mqtt"]}]}]}' -H "X-Token:"
  ```

## Schema

### MQTT Event Schema
```
{
  ...
  "result": {
    "data": {
      "connected": <boolean>,
      "auth": <boolean>,
      "messages": ["string"],
      "topics": ["string"],
      "num_events": number,
      "num_topics": number,
      "bytes_captured": number,
      "connack": { connack packet }
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

```
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
