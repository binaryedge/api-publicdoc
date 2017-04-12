# Port

The Port event is the default event that runs with every job.

## Port Request Example

```
curl -v -L https://api.binaryedge.io/v1/tasks -d '{"type":"scan", "options":[{"targets":["X.X.X.X"], "ports":[{"port":80, "protocol":"tcp", "modules":[]}]}]}' -H "X-Token:<Token>"
```

## Port Event Example

```json
{
  "origin": {
    "type": "port",
    "job_id": "client-816f1185-4bc1-4b5f-9a7d-61a2df315a6b",
    "client_id": "client",
    "country": "uk",
    "module": "portscan",
    "ts": 1453385574412
  },
  "target": {
    "ip": "X.X.X.X",
    "port": 80,
    "protocol": "tcp"
  },
  "result":{
  	"response":"synack"
  }
}
```
