# VNC

Grab VNC information and screenshots.

## Schema

### VNC Event Schema
```
{
  ...
  "result": {
    "data": {
      "title": "string",
      "width": int,
      "height": int,
      "version": "string",
      "link": "string",
      "auth_enabled": "boolean"
      "msg": "string"
    }
  }
}
```

### Contents of the fields:

  * title - Title returned by the VNC server
  * width - Width of the screen
  * height - Height of the screen
  * version - Version of the VNC Protocol
  * link - URL link to the screenshot
  * msg - Warning sent by the server, for example, "Too many security failures".

## VNC Event Example

```
{
  "origin": {
    "type": "vlc",
    "job_id": "client-816f1185-4bc1-4b5f-9a7d-61a2df315a6b",
    "client_id": "client",
    "country": "uk",
    "module": "grabber",
    "ts": 1453385574412
  },
  "target": {
    "ip": "X.X.X.X",
    "port": 5900,
    "protocol": "tcp"
  },
  "result": {
    "data": {
      "title": "TC13:0.0",
      "width": 1280,
      "height": 1024,
      "version": "RFB 003.007",
      "link": "https://url/to/image.jpg"
      "auth_enabled": "false"
    }
  }
}
```
