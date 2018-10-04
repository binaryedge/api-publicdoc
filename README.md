# How to use BinaryEdge’s API

<p align="center"><img src ="https://dl.dropboxusercontent.com/s/sgwwkchh59nrhgk/how_to_use_api_2.png?dl=0" /></p>

Note: all requests are identified by Job ID and are shown in the stream window.


|   | Input                                                                                                                                                                                                                                                                                                   | Output                                                    |
|---|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------|
| 1 | Connect to Data Stream <br> `$ curl https://stream.api.binaryedge.io/v1/stream -H "X-Token:InsertYourClientToken" `                                                                                                                                                                                                                                     | (data stream)                                             |
| 2 | Request a Scan Task <br> `$ curl https://api.binaryedge.io/v1/tasks -d '{"type":"scan", "description": "InsertYourDescriptionHere", "options":[{"targets":["InsertAnIPAddress/IPNetwork"], "ports":[{"port":InsertPort, "protocol": "tcp or udp", "modules": ["InsertModule"]}]}]}' -v -H "X-Token:InsertYourClientToken"` | {"stream_url":"stream URL","job_id":"Job ID"}             |


## Index

  * [Data Stream](#data-stream)
    * [1. firehose](#1-firehose)
    * [2. stream](#2-stream)
    * [3. torrent](#3-torrent)
    * [4. sinkhole](#4-sinkhole)

  * [Tasks](#tasks)
    * [GET /v1/tasks - List Requested Jobs](#get-v1tasks---list-requested-jobs)
    * [POST /v1/tasks - Create Job](#post-v1tasks---create-scan-job)
    * [POST /v1/tasks/job_id/revoke - Job Revoke](#post-v1tasksjob_idrevoke---revoke-job)
    * [GET /v1/replay/job_id - Replay Job](#get-v1replayjob_id---replay-job)
    * [Job Status](#job-status)
    * [Supported Types](#supported-job-types)
      * [1. scan](#1-scan)
      * [2. grab](#2-grab)

  * [General Data Format](#general-data-format)

  * [Supported Modules](#supported-modules-types)
    * [1. elasticsearch](#1-elasticsearch)
    * [2. http & https](#2-http--https)
    * [3. memcached](#3-memcached)
    * [4. mongodb](#4-mongodb)
    * [5. mqtt](#5-mqtt)
    * [6. rdp](#6-rdp)
    * [7. redis](#7-redis)
    * [8. service](#8-service)
    * [9. service-simple](#9-service-simple)
    * [10. ssh](#10-ssh)
    * [11. ssl](#11-ssl)
    * [12. telnet](#12-telnet)
    * [13. vnc](#13-vnc)
    * [14. web](#14-web)
    * [15. x11](#15-x11)

  * [Configurations](#configurations)

  * [Query Endpoints](#query-endpoints)
    * [Historical Query](#historical-query)
      * [GET /v1/query/historical](#get-v1queryhistorical---historical-ip-data-endpoint)
      * [GET /v1/query/latest](#get-v1querylatest---latest-ip-data-endpoint)
      * [GET /v1/query/torrent](#get-v1querytorrent---torrent-ip-data-endpoint)
      * [GET /v1/query/search](#get-v1querysearch---full-text-search)
      * [Error Messages in Historical Query](#error-messages-in-historical-query)

    * [Remote Desktop Query](#remote-desktop-query)
      * [GET /v1/query/image/ip/<ip>(options)](#get-v1queryimageipoptions)
      * [GET /v1/query/image](#get-v1queryimage)
      * [GET /v1/query/image/<image_id>?(options)](#get-v1queryimageimage_idoptions)
      * [GET /v1/query/image/search?(options)](#get-v1queryimagesearchoptions)
      * [GET /v1/query/image/search?similar=<image_id>](#get-v1queryimagesearchsimilarimage_id)
      * [Error Messages in Remote Desktop Query](#error-messages-in-remote-desktop-query)

## Data Stream

Continuous Data Stream of events generated by our platform.

```
Important: The Stream might disconnect sometimes, as such, it is the client's responsibility to reconnect, as it might miss results while disconnected. However, no data is really lost, since there is always the possibility of replay.
```

There are 2 types of Data Streams available that can be consumed, based on your client account permissions.

#### 1. Firehose

_Endpoint_: https://stream.api.binaryedge.io/v1/firehose

_Description_: This stream contains all data generated by Binaryedge own scans. These include the continuous WorldWide Scans that target different ports every day. This stream does not contain data generated from jobs requested by clients.

#### 2. Stream

_Endpoint_: https://stream.api.binaryedge.io/v1/stream

_Description_: This stream contains all data generated by your own requested Jobs. Clients don't have access to data generated from scans of other clients.

#### 3. Torrent

_Endpoint_: https://stream.api.binaryedge.io/v1/torrent

_Description_: This stream contains data generated by our listeners on the DHT, which is a series of events referring to "who is downloading what from whom".

See [Torrent Data](torrent.md) for details.

#### 4. Sinkhole

_Endpoint_: https://stream.api.binaryedge.io/v1/sinkhole

_Description_: This stream contains data generated by our "listen-only" machines, i.e., what everyone else has been scanning on our machines.

See [Sinkhole Data](sinkhole.md) for details.

## Tasks

### GET /v1/tasks - List Requested Jobs

Retrieve a list of the latest requested jobs. This includes:

  * "status": Status of the job. Where status can be:
    * "requested": Job was requested successfully;
    * "revoked": Job was revoked by user;
    * "success": Job completed successfully;
    * "failed": Job completed, but did not finish.
  * "requested_at": Time the job was requested;
  * "finished_at": Time the job finished;
  * "job_id": ID of the requested job;
  * "options": Job configuration options.

```
$ curl https://api.binaryedge.io/v1/tasks -H "X-Token:InsertYourClientToken"

HTTP/1.1 200 OK

[{"status": "Success", "requested_at": "2017-04-10T17:44:58.636681+00:00", "description": "Job Description 1", "finished_at": "2017-04-10T17:47:46.534544+00:00", "options": [{"targets": ["xxx.xxx.xxx.xxx"], "ports": [{"modules": ["service", "service-simple", "ssh"], "port": "80,8080"}]}], "job_id": "32637b98-8f01-46eb-a1f7-3eaee18ab1d5"}, {"status": "Success", "requested_at": "2017-04-10T17:39:53.066632+00:00", "description": "Test web", "finished_at": "2017-04-10T17:41:57.919141+00:00", "options": [{"targets": ["example.org"], "ports": [{"config": {"https": true}, "modules": ["web"], "port": 443}]}], "job_id": "73364d62-d768-4dbd-9947-aba2a453dfb7"}]
```

### POST /v1/tasks - Create Scan Job

Create a On-Demand Job. You can specify your own targets, ports, modules and configurations.

Parameters:

  * "type": "scan" or "grab". Please refer to [Supported Types](#supported-types);
  * "description": Add your own description of the job. Can be a empty string, i.e. "" ;
  * "options": Configuration Options for the job, array of JSON objects. 1 Job can have multiple options.

```
$ curl https://api.binaryedge.io/v1/tasks -d '{"type":"scan", "description": "InsertYourDescriptionHere", "options":[{"targets":["InsertAnIPAddress/IPNetwork"], "ports":[{"port":InsertPort, "protocol": "tcp or udp", "modules": ["InsertModule"]}]}]}' -v -H "X-Token:InsertYourClientToken"
```

### POST /v1/tasks/job_id/revoke - Revoke Job

To cancel a requested job:

```
$ curl -XPOST https://api.binaryedge.io/v1/tasks/<JOB_ID>/revoke -H  "X-Token:InsertYourClientToken"

HTTP/1.1 200 OK
{"message": "Job revoked"}
```

### GET /v1/replay/job_id - Replay Job

To retrieve the results from a previously requested scan job, you can replay the stream with this endpoint.

```
$ curl https://stream.api.binaryedge.io/v1/replay/<JOB_ID> -H "X-Token:InsertYourClientToken"

HTTP/1.1 200 OK
<Stream results from request job>
```

### Job Status

In order for you to know the status of your jobs we provide information in 2 distinct ways:

#### 1. GET /v1/tasks/job_id/status - Status Endpoint

To check the current status of a Requested job:

```
$ curl https://api.binaryedge.io/v1/tasks/<job_id>/status -H "X-Token:InsertYourClientToken"

HTTP/1.1 200 OK
{"status":"<STATUS>"}
```

Where Status can be:

  * "requested": Job was requested successfully;
  * "revoked": Job was revoked by user;
  * "success": Job completed successfully;
  * "failed": Job completed, but did not finish.

#### 2. Status Messages inside stream

In your stream you will find messages providing insight on the current status of your jobs:

**Job Created**

```json
{
  "origin": {
    "job_id": "c4773cb-aa1e-4356eac1ad08",
    "type": "job_status",
    ...
  },
  "status": {
    "success": null,
    "started": null,
    "completed": null,
    "revoked": null
  }
}
```

**Job Completed**

```json
{
  "origin": {
    "job_id": "c4773cb-aa1e-4356eac1ad08",
    "type": "job_status",
    ...
  },
  "status": {
    "success": true,
    "started": true,
    "completed": true,
    "revoked": false
  }
}
```

Meaning of the status fields:

  * "success": If the job was completed successfully, with no problems;
  * "started": When a job is requested, it is put into a queue;
  * "completed": If the job is completed, no more results will be sent;
  * "revoked": If the job was canceled by the user or not.


### Supported Job Types

There are 2 types of requests.

### 1. scan
The scan type will request a portscan on the targets and will launch the modules against the detected open ports. It should be used against a large number of targets and its function is to filter responding IPs. Note: scanning only works with IP addresses, not domains.

### 2. grab
The grab type will try to gather information directly from the targets, without portscanning first. Should be used against a small number of targets.

Recommended for when targeting Domains, with Web and HTTP/HTTPS modules. 


## General Data Format

All events generated by our scanning platform, delivered via our Data Streams, have the following outline (except the Status messages presented above):

Details of the fields:

* **origin**: 
  * **client_id**:
    * Only on client stream,
    * Your client ID;
  * **job_id**:
    * Only on client stream,
    * Job ID that event is part of;
  * **type**:
    * Event type, module that produced the event,
    * Please refer to the next section for details on each module type;
  * **module**:
    * Either 'portscan' or 'grabber'. Category of the event. Portscan events merely indicate that a port was found open. Grabber events will contain more extracted data such as details of the ip/port/service;
  * **ip**:
    * IP used by the scanner to perform the analysis;
  * **port**:
    * Port used by the scanner to perform the analysis. Optional, only some modules will provide this information. Currently only provided by "service-simple". We will be working to add more.
    * Port used by the scanner to perform the analysis;
  * **ts**:
    * Unix Timestamp in Milliseconds;
  * **country**:
    * ISO code of the country the scanner that originated this event is located in;
* **target**: 
  * **ip**:
    * Target Address used for connection;
  * **port**:
    * Target Port used for connection;
  * **protocol**:
    * Target Protocol used for connection;
* **result**: 
  * **data**:
    * Varies according to each different module,
    * Please refer to the next section for details on each module type.


```
{
  "origin": {
    "client_id": "string",
    "job_id": "string",
    "country": "string",
    "type": "string",
    "module": "string",
    "ts": integer,
    "ip": "string"
    "port": integer
  },
  "target": {
    "ip": "ip",
    "port": integer,
    "protocol": "string"
  },
  "result": {
    "data": {(...)}  
  }
}
```

## Supported Modules Types

### 1. elasticsearch
_Description_: Extract Elasticsearch detailed information.

_Detailed documentation_: [elasticsearch module documentation](modules/elasticsearch.md "elasticsearch")

### 2. http & https
_Description_: Extract HTTP/HTTPS information, e.g. HTTP headers, HTTP status codes, HTTP body, and redirects information. Follows up to 5 redirects.

_Detailed documentation_: [http & https module documentation](modules/http.md "http")

### 3. memcached
_Description_: Extract Memcached detailed information.

_Detailed documentation_: [memcached module documentation](modules/memcached.md "memcached")

### 4. mongodb
_Description_: Extract MongoDB detailed information.

_Detailed documentation_: [mongodb module documentation](modules/mongodb.md "mongodb")

### 5. mqtt
_Description_: Grab MQTT information, including messages and topics.

_Detailed documentation_: [mqtt module documentation](modules/mqtt.md "mqtt")

### 6. rdp
_Description_: Extract RDP details and screenshot.

_Detailed documentation_: [rdp module documentation](modules/rdp.md "rdp")

### 7. redis
_Description_: Extract Redis detailed information.

_Detailed documentation_: [redis module documentation](modules/redis.md "redis")

### 8. service
_Description_: Extract detailed product specific information, e.g. product name, version, headers, scripts. If you just want product name and version, consider using the faster "service-simple".

_Detailed documentation_: [service module documentation](modules/service.md "service")

### 9. service-simple
_Description_: Extract basic product specific information, e.g. product name, version. This module is much faster than "service", since it returns less information.

_Detailed documentation_: [service-simple module documentation](modules/service-simple.md "service-simple")

### 10. ssh

_Description_: Extract SSH details, e.g. key and algorithms for SSH servers.

_Detailed documentation_: [ssh module documentation](modules/ssh.md "ssh")

### 11. ssl
_Description_: Extract SSL details e.g. type of encryption.

_Detailed documentation_: [ssl module documentation](modules/ssl.md "ssl")

### 11.2 sslv2
_Description_: Extract SSL details (Version 2).

_Detailed documentation_: [sslv2 module documentation](modules/sslv2.md "sslv2")

### 12. telnet
_Description_: Extract Telnet information, e.g. Will, Do, Don't Won't commands.

_Detailed documentation_: [telnet module documentation](modules/telnet.md "telnet")

### 13. vnc
_Description_: Extract VNC details and screenshot.

_Detailed documentation_: [vnc module documentation](modules/vnc.md "vnc")

### 14. web
_Description_: Extract Web technologies information and headers.

_Detailed documentation_: [web module documentation](modules/web.md "web")

### 15. x11
_Description_: Extract x11 screenshot.

_Detailed documentation_: [x11 module documentation](modules/x11.md "x11")

### *Custom Modules*
Note: If you want a custom-made module, please contact BinaryEdge.

## Configurations
It is possible to set module specific configurations on the job requests. For example, the HTTP module allows the configuration of the Host and the User Agent HTTP headers.
The configuration should be set in the "config" key at the same json level of the requested module.

Example:

```json
{
  "type": "scan",
  "description": "test a bunch of networks",
  "options": [
    {
      "targets": ["xxx.xxx.x.x/xx","xxx.xxx.x.x/xx"],
      "ports": [
        {
        "port": 80,
        "modules": ["http"],
        "config":
          {
            "user_agent":"Test user Agent",
            "host_header":"google.com"
          }
        }
      ]
    }
  ]
}
```

### Available configurations

Check each module's detailed documentation for the available configurations.

## Query Endpoints

### Historical Query

#### GET /v1/query/historical - Historical IP Data Endpoint

Access our historical database. This will provide with all the raw events regarding an IP

Available options:

  * Target IP, e.g.:
    * /v1/query/historical/210.1.1.X
  * Target CIDR, e.g.:
    * /v1/query/historical/210.1.1.X/24
  * Target Range, e.g.:
    * /v1/query/historical/210.1.1.X-210.1.1.Y

```
$ curl -v https://api.binaryedge.io/v1/query/historical/222.208.xxx.xxx -H 'X-Token:InsertYourClientToken'
```

##### Response

```json
{
  "origin": {
    "country": "uk",
    "module": "grabber",
    "ts": 1464558594512,
    "type": "service-simple"
  },
  "target": {
    "ip": "222.208.xxx.xxx",
    "protocol": "tcp",
    "port": 992
  },
  "result": {
    "data": {
      "state": {
        "state": "open|filtered"
      },
      "service": {
        "name": "telnets",
        "method": "table_default"
      }
    }
  }
}
```

#### GET /v1/query/latest - Latest IP Data Endpoint

Access our historical database. This will provide with the latest raw events regarding an IP

Available options:

  * Target IP, e.g.:
    * /v1/query/latest/210.1.1.X
  * Target CIDR, e.g.:
    * /v1/query/latest/210.1.1.X/24
  * Target Range, e.g.:
    * /v1/query/latest/210.1.1.X-210.1.1.Y

```
$ curl -v https://api.binaryedge.io/v1/query/latest/222.208.xxx.xxx -H 'X-Token:InsertYourClientToken'
```

##### Response

```json
{
  "origin": {
    "country": "uk",
    "module": "grabber",
    "ts": 1464558594512,
    "type": "service-simple"
  },
  "target": {
    "ip": "222.208.xxx.xxx",
    "protocol": "tcp",
    "port": 992
  },
  "result": {
    "data": {
      "state": {
        "state": "open|filtered"
      },
      "service": {
        "name": "telnets",
        "method": "table_default"
      }
    }
  }
}
```

#### GET /v1/query/torrent - Torrent IP Data Endpoint

Access our historical database. This will provide with raw events related with torrent activity regarding an IP

Available options:

  * Target IP, e.g.:
    * /v1/query/torrent/210.1.1.X
  * Target CIDR, e.g.:
    * /v1/query/torrent/210.1.1.X/24
  * Target Range, e.g.:
    * /v1/query/torrent/210.1.1.X-210.1.1.Y

```
$ curl -v https://api.binaryedge.io/v1/query/torrent/222.208.xxx.xxx -H 'X-Token:InsertYourClientToken'
```

##### Response

```json
{
  "origin":{  
    "type":"peer",
    "module":"torrent",
    "ts":1491827676263
  },
  "node":{  
    "ip":"219.88.xxx.xxx",
    "port":25923
  },
  "peer":{  
    "ip":"222.208.xxx.xxx",
    "port":30236
  },
  "torrent":{  
    "infohash":"cbe45addbb48c07ef6451bd3bee326d5cd82538f",
    "name":"NCIS Los Angeles S08E20 HDTV x264-LOL EZTV",
    "source":"EZTV",
    "category":"TV Show"
  }
}
```

#### GET /v1/query/torrent/latest - Latest Torrent IP Data Endpoint

Access our historical database. This will provide with latest raw events related with torrent activity regarding an IP

Available options:

  * Target IP, e.g.:
    * /v1/query/torrent/latest/210.1.1.X
  * Target CIDR, e.g.:
    * /v1/query/torrent/latest/210.1.1.X/24
  * Target Range, e.g.:
    * /v1/query/torrent/latest/210.1.1.X-210.1.1.Y

```
$ curl -v https://api.binaryedge.io/v1/query/torrent/latest/222.208.xxx.xxx -H 'X-Token:InsertYourClientToken'
```

##### Response

```json
{
  "origin":{  
    "type":"peer",
    "module":"torrent",
    "ts":1491827676263
  },
  "node":{  
    "ip":"219.88.xxx.xxx",
    "port":25923
  },
  "peer":{  
    "ip":"222.208.xxx.xxx",
    "port":30236
  },
  "torrent":{  
    "infohash":"cbe45addbb48c07ef6451bd3bee326d5cd82538f",
    "name":"NCIS Los Angeles S08E20 HDTV x264-LOL EZTV",
    "source":"EZTV",
    "category":"TV Show"
  }
}
```

#### GET /v1/query/search - Full-Text Search 

Query our data, using our Text Search Engine.

```
$ curl -v https://api.binaryedge.io/v1/query/search\?query\="mysql" -H 'X-Token:InsertYourClientToken'
```

Or, you can use some filters:

Available options:

  * product: (string) search product names, e.g. "nginx"
  * country: (string) search using country codes, e.g. "ES"
  * port: (int) filter by port number, e.g. 80
  * Conditionals: the following conditionals are available: AND, OR. Must be UPPERCASE.

```
$ curl -v https://api.binaryedge.io/v1/query/search\?query\="product:mysql%20AND%20country:ES" -H 'X-Token:InsertYourClientToken'
```

#### Error Messages in Historical Query

Performing a malformed query:

```
HTTP/1.1 400 Bad Request
  {
      "status": 400,
      "title": "Bad Request",
      "message": "Parameters with wrong format/type or ill-defined, please review your query"
  }
```

Sending invalid Token:

```
HTTP/1.1 401 Unauthorized
{
    "status": 401,
    "title": "Unauthorized",
    "message": "Could not validate token, please review your token"
}
```

### Remote Desktop Query

#### GET /v1/query/image/ip

Query details about remote desktops that were detected by BinaryEdge for a specific IP. This includes the following information:

  * ip: string, target address where the screenshot was taken;
  * port: integer, target port where the service was running;
  * ts: integer, timestamp of when the screenshot was taken;
  * geoip: object, geographical information;
  * has_faces: boolean, whether faces were detected or not;
  * n_faces: integer, Number of faces detected on the image;
  * tags: list of string, tags automatically attributed by our process;
  * height: integer;
  * width: integer;
  * url: String, URL to download image;
  * thumb: SString, URL to download image thumbnail;

Available options:

  * ocr: if present, shows an additional "words" field, which is a list of words obtains via our OCR process, e.g.:
    * ocr=1

```
$ curl -v https://api.binaryedge.io/v1/query/image/ip/XXX.XXX.XXX.XXX?ocr=1 -H 'X-Token:InsertYourClientToken'
```

##### Response

```json
{
  "total_records": 3,
  "page": 1,
  "events": [
    {
      "image_id": "993cad4bb78fc0fa3e8f5f1d07311af802ea73ac48b6143c6286ae54df",
      "asn": 5432,
      "url": "https://d1ngxp4ef6grqi.cloudfront.net/993cad4bb78fc0fa3e8f5f1d07311af802ea73ac48b6143c6286ae54df.jpg",
      "width": 1280,
      "as_name": "Proximus NV",
      "thumb": "https://d3f9qnon04ymh2.cloudfront.net/993cad4bb78fc0fa3e8f5f1d07311af802ea73ac48b6143c6286ae54df.jpg",
      "geoip": {
        "country_code": "BE",
        "city_name": null,
        "timezone": "Europe/Brussels",
        "longitude": 4.35,
        "country_name": "Belgium",
        "latitude": 50.85,
        "location": [
          4.35,
          50.85
        ]
      },
      "tags": [
        "vnc"
      ],
      "words": [
        "show",
        "results",
        "user",
        "mediline",
        "logged",
        "out",
        "userlevel"
      ],
      "height": 800,
      "port": 5900,
      "country": "BE",
      "ip": "81.246.69.245",
      "ts": 1536345753000
    }
  ]
}
```

#### GET /v1/query/image

Query for a list of remote desktops found (latest first).

Available options:

  * pagesize: Maximum number of results to return per page
    * pagesize=100
  * page: Page number of the results
    * page=1

```
$ curl -v https://api.binaryedge.io/v1/query/image -H 'X-Token:InsertYourClientToken'
```

##### Response

```json
{
  "total_records": 3,
  "page": 1,
  "events": [
    {
      "url": "https://d1ngxp4ef6grqi.cloudfront.net/9034b457b18ddbe236915407063215f201e214c24cb11a3c6287ae58dd24.jpg",
      "thumb": "https://d3f9qnon04ymh2.cloudfront.net/9034b457b18ddbe236915407063215f201e214c24cb11a3c6287ae58dd24.jpg",
      "image_id": "9034b457b18ddbe236915407063215f201e214c24cb11a3c6287ae58dd24"
    },
    {
      "url": "https://d1ngxp4ef6grqi.cloudfront.net/9035b057b197dcfe338f5a1e08381cf90a851da945b6163b618bae52.jpg",
      "thumb": "https://d3f9qnon04ymh2.cloudfront.net/9035b057b197dcfe338f5a1e08381cf90a851da945b6163b618bae52.jpg",
      "image_id": "9035b057b197dcfe338f5a1e08381cf90a851da945b6163b618bae52"
    },
    {
      "url": "https://d1ngxp4ef6grqi.cloudfront.net/903db057b788c0f929935f1b08381cf90a851da945b6163b618bab56.jpg",
      "thumb": "https://d3f9qnon04ymh2.cloudfront.net/903db057b788c0f929935f1b08381cf90a851da945b6163b618bab56.jpg",
      "image_id": "903db057b788c0f929935f1b08381cf90a851da945b6163b618bab56"
    }
  ]
}
```

#### GET /v1/query/image

Query details about remote desktops that were detected by BinaryEdge. This includes the following information:

  * ip: string, target address where the screenshot was taken;
  * port: integer, target port where the service was running;
  * ts: integer, timestamp of when the screenshot was taken;
  * geoip: object, geographical information;
  * has_faces: boolean, whether faces were detected or not;
  * n_faces: integer, Number of faces detected on the image;
  * tags: list of string, tags automatically attributed by our process;
  * height: integer;
  * width: integer;
  * url: String, URL to download image;
  * thumb: SString, URL to download image thumbnail;

Available options:

  * ocr: if present, shows an additional "words" field, which is a list of words obtains via our OCR process, e.g.:
    * ocr=1

```
$ curl -v https://api.binaryedge.io/v1/query/image/f1b0a311af803ea73ac48adce2378f58adce2378f5?ocr=1 -H 'X-Token:InsertYourClientToken'
```

##### Response

```json
{
  "image_id": "993cad4bb78fc0fa3e8f5f1d07311af802ea73ac48b6143c6286ae54df",
  "asn": 5432,
  "url": "https://d1ngxp4ef6grqi.cloudfront.net/993cad4bb78fc0fa3e8f5f1d07311af802ea73ac48b6143c6286ae54df.jpg",
  "width": 1280,
  "as_name": "Proximus NV",
  "thumb": "https://d3f9qnon04ymh2.cloudfront.net/993cad4bb78fc0fa3e8f5f1d07311af802ea73ac48b6143c6286ae54df.jpg",
  "geoip": {
    "country_code": "BE",
    "city_name": null,
    "timezone": "Europe/Brussels",
    "longitude": 4.35,
    "country_name": "Belgium",
    "latitude": 50.85,
    "location": [
      4.35,
      50.85
    ]
  },
  "tags": [
    "vnc"
  ],
  "words": [
    "show",
    "results",
    "user",
    "mediline",
    "logged",
    "out",
    "userlevel"
  ],
  "height": 800,
  "port": 5900,
  "country": "BE",
  "ip": "81.246.69.245",
  "ts": 1536345753000
}
```

#### GET /v1/query/image/search

Query for a list of remote desktops according to certain filters.

Available options:

  * ip: IP, CIDR or Range you want to target, e.g.:
    * ip=127.0.0.1
  * port: Port number /range you want to target, e.g.:
    * port=5900
  * country: Search images from a certain country, e.g.:
    * country=pt
  * tag: Search images that contain a tag, e.g.:
    * tag=has_faces
    * tag=mobile
  * word: Search images that contain a word, e.g.:
    * word=microsoft
    * word=credit+card
  * from: Start date (or meaningful string) of the timerange you want to retrieve images from, e.g.:
    * from=2015-01-01
  * to: End date (or meaningful string) of the timerange you want to retrieve images from, e.g.:
    * to=2018-01-01
  * pagesize: Maximum number of results to return per page
    * pagesize=100
  * page: Page number of the results
    * page=1

```
$ curl https://api.binaryedge.io/v1/query/image/search\?ip\=120.XXX.XXX.XXX  -H 'X-Token:InsertYourClientToken'
```

##### Response

```json
{
  "total_records": 3,
  "page": 1,
  "query": {
    "ip": "58.56.83.212",
    "port": 5900,
    "country": "CN",
    "face": true,
    "tag": "vnc",
    "logo": "windows",
    "word": "confidential OR private"
  },
  "events": [
    {
      "url": "https://d1ngxp4ef6grqi.cloudfront.net/903cb557b597d9fa29905e1908381cf90b851da945b711366686af50.jpg",
      "thumb": "https://d3f9qnon04ymh2.cloudfront.net/903cb557b597d9fa29905e1908381cf90b851da945b711366686af50.jpg",
      "image_id": "903cb557b597d9fa29905e1908381cf90b851da945b711366686af50"
    },
    {
      "url": "https://d1ngxp4ef6grqi.cloudfront.net/933db157b280dfe236975e07073315f201e215c24cb11a3d658ba054dd21.jpg",
      "thumb": "https://d3f9qnon04ymh2.cloudfront.net/933db157b280dfe236975e07073315f201e215c24cb11a3d658ba054dd21.jpg",
      "image_id": "933db157b280dfe236975e07073315f201e215c24cb11a3d658ba054dd21"
    },
    {
      "url": "https://d1ngxp4ef6grqi.cloudfront.net/9735ad48b289c0f9338f5c1908381cf90b851da945b712386387ac59.jpg",
      "thumb": "https://d3f9qnon04ymh2.cloudfront.net/9735ad48b289c0f9338f5c1908381cf90b851da945b712386387ac59.jpg",
      "image_id": "9735ad48b289c0f9338f5c1908381cf90b851da945b712386387ac59"
    }
  ]
}
```

#### GET /v1/query/image/search

Query for a list of remote desktops that are similar to another remote desktop.
Note: This option cannot be used together with the previous ones.

```
$ curl https://api.binaryedge.io/v1/query/image/search\?similar\=f1b0a311af803ea73ac48adce2378f58adce2378f5  -H 'X-Token:InsertYourClientToken'
```

##### Response

```json
{
  "total_records": 3,
  "page": 1,
  "events": [
    {
      "url": "https://d1ngxp4ef6grqi.cloudfront.net/9538ad4ab697d6e236935913013817f96deb18aa45b11a3d638aab.jpg",
      "thumb": "https://d3f9qnon04ymh2.cloudfront.net/9538ad4ab697d6e236935913013817f96deb18aa45b11a3d638aab.jpg",
      "score": 26.099752,
      "image_id": "9538ad4ab697d6e236935913013817f96deb18aa45b11a3d638aab",
      "dist": 0
    },
    {
      "url": "https://d1ngxp4ef6grqi.cloudfront.net/9538ad4ab697d6e236935e13013817f96deb18aa4abd133f638ba8.jpg",
      "thumb": "https://d3f9qnon04ymh2.cloudfront.net/9538ad4ab697d6e236935e13013817f96deb18aa4abd133f638ba8.jpg",
      "score": 26.01995,
      "image_id": "9538ad4ab697d6e236935e13013817f96deb18aa4abd133f638ba8",
      "dist": 0
    },
    {
      "url": "https://d1ngxp4ef6grqi.cloudfront.net/9538ad4ab697d6e236935c13013817f96deb18aa4ab2143c6087a9.jpg",
      "thumb": "https://d3f9qnon04ymh2.cloudfront.net/9538ad4ab697d6e236935c13013817f96deb18aa4ab2143c6087a9.jpg",
      "score": 26.01995,
      "image_id": "9538ad4ab697d6e236935c13013817f96deb18aa4ab2143c6087a9",
      "dist": 0
    }
  ]
}
```

#### Error Messages in Remote Desktop Query

Performing a malformed query:

```
HTTP/1.1 400 Bad Request
{
    "status": 400,
    "title": "Bad Request",
    "message": "Parameters with wrong format/type or ill-defined, please review your query"
}
```

Sending invalid Token:

```
HTTP/1.1 401 Unauthorized
{
    "status": 401,
    "title": "Unauthorized",
    "message": "Could not validate token, please review your token"
}
```

Accessing a page that does not exist:

```
{
    "status": 404,
    "title": "Not Found",
    "message": "Page not found"
}
```

### FAQ

**Q: What is the sample parameter?**

**A:** The Sample parameter is used to define how many open ports the platform needs to find before stopping the scan. It is useful to test modules and different configurations for each module (that we are adding in the future). This parameter is optional - by default the scan stops only after scanning the entire list of IP addresses and ports.


**Q: How can I consume the stream?**

**A:** The stream outputs to STDOUT, allowing you to consume it in different ways. For example:

- Direct the stream to a file:
    - `curl https://stream.api.binaryedge.io/v1/stream -H "X-Token:InsertYourClientToken" > file.txt`
- Pipe the stream to a custom application you developed to process it:
    - `curl https://stream.api.binaryedge.io/v1/stream -H "X-Token:InsertYourClientToken" | application_name `


**Q: What should I do if I get a error 500?**

**A:** In this case, you should contact support@binaryedge.io


**Q: How do I scan multiple hosts with one request?**

**A:**

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

Example:

```json
{
   "type": "scan",
   "description": "test a bunch of networks",
   "options": [
       {
         "targets": ["xxx.xxx.x.x/xx","xxx.xxx.x.x/xx"],
         "ports": [{
            "port": 995,
            "modules": ["service"]
           },
           {
            "port": 22,
            "modules": ["ssh"]
           }]
       }, {
         "targets": ["xxx.xxx.x.x/xx"],
         "ports": [{
            "port": 5900,
            "modules": ["vnc"]
         }]
       }
     ]
 }
 ```
