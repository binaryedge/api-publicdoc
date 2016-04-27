# Query

The API provides an interface to query previously captured data, without the need to run a new scan job.

Currently, the query endpoint only supports 1 type of service, VNC.

## Endpoints

### VNC

VNC allows to get a screenshot associated with a particular IP.

`curl https://api.binaryedge.io/v1/query/vnc/X.X.X.X -H "X-Token:InsertYourClientToken" `

```
{
	"target": {
		"ip": "X.X.X.X"
	},
	"vnc": {
		"5900.tcp": {
			"title": "stmd:0",
			"ts": 1453145187727,
			"height": "768",
			"width": "1024",
			"version": "3.8",
			"link": "https://path/to/image.jpg",
			"auth_enabled": "false"
		}
	}
}
```

## Client Errors

Sending invalid IP:

```
HTTP/1.1 400 Bad Request
{"message": "Invalid ips given"}
```

Sending an IP with no records:

```
HTTP/1.1 404 Not Found
{"message": "No records found"}
```
