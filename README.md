# How to use BinaryEdge’s API


<p align="center"><img src ="https://dl.dropboxusercontent.com/s/rk8m8jlf2z8ay5j/how%20to%20use%20api.png?dl=0: 200px;" /></p>

Note: all requests are identified by Job ID and are shown in the stream window.










|   | Input                                                                                                                                                                                                                                                                                                   | Output                                                    |
|---|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------|
| 1 | `curl -v http://api.binaryedge.io/v1/login -H 'X-APP-ID: InsertAnAppID' -H 'X-USER-ID: InsertYourUserID' `                                                                                                                                                                                        | {"client_token":"client token","stream_url":"stream URL"} |
| 2 | `curl insert your stream URL -H 'X-Token: InsertYourClientToken' `                                                                                                                                                                                                                                     | (data stream)                                             |
| 3 | `curl http://api.binaryedge.io/v1/tasks -d '{"type":"scan", "description": "InsertYourDescriptionHere", "options":[{"targets":["InsertAnIPAddress/IPNetwork"], "ports":[{"port":InsertPort, “sample”: InsertSampleSize, "modules": ["InsertModule"]}]}]}' -v -H 'X-Token:InsertYourClientToken'` | {"stream_url":"stream URL","job_id":"Job ID"}             |




### Supported Modules



#####1. ssh

_Description_: Extract SSH key and algorithms for SSH servers

_Detailed documentation_: [ssh module documentation](https://github.com/binaryedge/api-publicdoc/blob/master/ssh.md "ssh")


#####2. ssl
_Description_: Extract SSL type of encryption

_Detailed documentation_: [ssl module documentation](https://github.com/binaryedge/api-publicdoc/blob/master/ssl.md "ssl")

#####3. vnc
_Description_: Grab VNC information and screenshots

_Detailed documentation_: [vnc module documentation](https://github.com/binaryedge/api-publicdoc/blob/master/vnc.md "vnc")


#####4. service
_Description_: Extract product specific information from a remote address

_Detailed documentation_: [service module documentation](https://github.com/binaryedge/api-publicdoc/blob/master/service.md "service")



Note: If you want a custom-made module, please contact BinaryEdge.





### FAQ

**Q:** What is the sample parameter?

**A: ** The Sample parameter is used to define how many open ports the platform needs to find before stopping the scan. It is useful to test modules and different configurations for each module (that we are adding in the future). This parameter is optional - by default the scan stops only after scanning the entire list of IP addresses and ports.

**Q:** How do I scan multiple hosts with one request?

**A: **

```
options: [{
   "targets": [array of cidrs (string)],
   "ports": [{
       "port": int,
       "modules": [array of module names (string)],
       "sample": int
   }]
}]
```

for example:

```
{
   "type": "scan",
   "description": "test a bunch of networks",
   "options": [
       {
         "targets": ["xxx.xxx.x.x/xx","xxx.xxx.x.x/xx"],
         "ports": [{
            "port": 995,
            "module": "service"
           },
           {
            "port": 22,
            "module": "ssh"
           }]
       }, {
         "targets": ["xxx.xxx.x.x/xx"],
         "ports": [{
            "port": 5900,
            "module": "vnc"
         }]
       }
     ]     
 }
 ```
