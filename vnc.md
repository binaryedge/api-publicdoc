# VNC

Grab VNC information and screenshots.

## Schema
##### VNC Event Schema
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
      "msg": "string"
    }
  },
  ...
}
```

##Contents of the fields:


title - Title returned by the VNC server

width - Width of the screen

height - Height of the screen

version - Version of the VNC Protocol

link - URL link to the screenshot

msg - Warning sent by the server, for example, "Too many security failures".
 

#### VNC Event Example 
```
{
  ...
  "result": {
    "data": {
      "title": "TC13:0.0",
      "width": 1280,
      "height": 1024,
      "version": "RFB 003.007",
      "link": "https://s3-eu-west-1.amazonaws.com/be-vnc-screens/vnc_212.182.21.41_5900_1446568457.jpg"
    }
  },
  ...
}
```