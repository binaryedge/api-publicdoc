# Service

The Service grabber tries to extract product specific information from a remote address.

### Service Event Example
```
{
   "origin":{
     "job_id": "XXXXX-a50e189f-dc61-48da-9ddb-3f12be0164ab",
     "type":"service",
     "minion": "min-29-9051-usnj-dev",
     "module": "grabber",
     "ts":1446504620000
   },
   "target":{
       "ip":"xx.xxx.xx.x",
       "port":80,
       "protocol":"tcp"
   },
   "result":
   {
    "data":
    {
      "service":
          {
              "name":"ssh",
              "product":"OpenSSH","version":"6.6.1p1 Ubuntu 2ubuntu2.3",
              "extrainfo":"Ubuntu Linux; protocol 2.0",
              "ostype":"Linux",
              "cpe":["cpe:/a:openbsd:openssh:6.6.1p1","cpe:/o:linux:linux_kernel"]
          },
      "script":
           [
               {
                   "id":"http-methods",
                   "output":"No Allow or Public header in OPTIONS response (status code 400)"
               },
               {
                   "id":"http-title",
                   "output":"Invalid URL",
                   scripts:
                   {
                   ....
                       <extra script information, dynamic because if depends on the script>
                   ....
                   }
               }
           ]
    }
   }
}
```
