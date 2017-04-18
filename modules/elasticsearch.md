# Elasticsearch

Extract Elasticsearch detailed information.

## Elasticsearch Request Example

```
curl -v -L https://api.binaryedge.io/v1/tasks -d '{"type":"scan", "options":[{"targets":["X.X.X.X"], "ports":[{"port":9200, "protocol":"tcp", "modules":["elasticsearch"]}]}]}' -H "X-Token:<Token>"
```

## Schema

### Elasticsearch Event Schema

```json
{
  ...
  "result": {
    "data": {
      "cluster_name": "string",
      "node_name": "string",
      "name": "string",
      "transport_address": "string",
      "host": "string",
      "ip": "string",
      "version": "string",
      "build": "string",
      "http_address": "string",
      "settings": {
        "client": {
          "type": "string"
        },
        "name": "string",
        "path": {
          "logs": "string",
          "home": "string"
        },
        "cluster": {
          "name": "string"
        },
        "cloud": {
          "aws": {
            "region": "string"
          }
        },
        "config": {
          "ignore_system_properties": "string"
        },
        "discovery": {
          "type": "string"
        },
        "network": {
          "host": "string"
        },
        "foreground": "string"
      },
      "os": {
        "refresh_interval_in_millis": "int",
        "name": "string",
        "arch": "string",
        "version": "string",
        "available_processors": "int",
        "allocated_processors": "int"
      },
      "process": {
        "refresh_interval_in_millis": "int",
        "id": "int",
        "mlockall": "boolean"
      },
      "jvm": {
        "pid": "int",
        "version": "string",
        "vm_name": "string",
        "vm_version": "string",
        "vm_vendor": "string",
        "start_time_in_millis": "int",
        "mem": {
          "heap_init_in_bytes": "int",
          "heap_max_in_bytes": "int",
          "non_heap_init_in_bytes": "int",
          "non_heap_max_in_bytes": "int",
          "direct_max_in_bytes": "int"
        },
        "gc_collectors": [
          "string"
        ],
        "memory_pools": [
          "string"
        ],
        "using_compressed_ordinary_object_pointers": "string"
      },
      "thread_pool": {
        "generic": {
          "type": "string",
          "keep_alive": "string",
          "queue_size": "int"
        },
        "index": {
          "type": "string",
          "min": "int",
          "max": "int",
          "queue_size": "int"
        },
        "fetch_shard_store": {
          "type": "string",
          "min": "int",
          "max": "int",
          "keep_alive": "string",
          "queue_size": "int"
        },
        "get": {
          "type": "string",
          "min": "int",
          "max": "int",
          "queue_size": "int"
        },
        "snapshot": {
          "type": "string",
          "min": "int",
          "max": "int",
          "keep_alive": "string",
          "queue_size": "int"
        },
        "force_merge": {
          "type": "string",
          "min": "int",
          "max": "int",
          "queue_size": "int"
        },
        "suggest": {
          "type": "string",
          "min": "int",
          "max": "int",
          "queue_size": "int"
        },
        "bulk": {
          "type": "string",
          "min": "int",
          "max": "int",
          "queue_size": "int"
        },
        "warmer": {
          "type": "string",
          "min": "int",
          "max": "int",
          "keep_alive": "string",
          "queue_size": "int"
        },
        "flush": {
          "type": "string",
          "min": "int",
          "max": "int",
          "keep_alive": "string",
          "queue_size": "int"
        },
        "search": {
          "type": "string",
          "min": "int",
          "max": "int",
          "queue_size": "int"
        },
        "fetch_shard_started": {
          "type": "string",
          "min": "int",
          "max": "int",
          "keep_alive": "string",
          "queue_size": "int"
        },
        "listener": {
          "type": "string",
          "min": "int",
          "max": "int",
          "queue_size": "int"
        },
        "percolate": {
          "type": "string",
          "min": "int",
          "max": "int",
          "queue_size": "int"
        },
        "refresh": {
          "type": "string",
          "min": "int",
          "max": "int",
          "keep_alive": "string",
          "queue_size": "int"
        },
        "management": {
          "type": "string",
          "min": "int",
          "max": "int",
          "keep_alive": "string",
          "queue_size": "int"
        }
      },
      "transport": {
        "bound_address": [
          "string"
        ],
        "publish_address": "string",
        "profiles": {}
      },
      "http": {
        "bound_address": [
          "string"
        ],
        "publish_address": "string",
        "max_content_length_in_bytes": "int"
      },
      "plugins": [
        {
          "name": "string",
          "version": "string",
          "description": "string",
          "jvm": "boolean",
          "classname": "string",
          "isolated": "boolean",
          "site": "boolean"
        }
      ],
      "modules": [
        {
          "name": "string",
          "version": "string",
          "description": "string",
          "jvm": "boolean",
          "classname": "string",
          "isolated": "boolean",
          "site": "boolean"
        },
        ...
      ]
    }
  }
}
```

### Contents of the fields:

*Variables description from https://www.elastic.co/guide/en/elasticsearch/reference/current/index.html*

* cluster_name - the cluster's name
* node_name - the node's name
* name - the database's name
* transport_address - host and port where transport HTTP connections are accepted
* host - the node’s host name
* ip - the node’s IP address
* version - shows the cluster state version
* build - short hash of the last git commit in this release.
* http_address - host and port where primary HTTP connections are accepted
* settings - diverse settings of elasticsearch
* os - the 'os' flag can be set to retrieve information that concern the operating system
* process - the process flag can be set to retrieve information that concern the current running process
* jvm - JVM stats, memory pool information, garbage collection, buffer pools, number of loaded/unloaded classes
* thread_pool - a node holds several thread pools in order to improve how threads memory consumption are managed within a node
* transport - transport statistics about sent and received bytes in cluster communication
* http - statistics about http communications
* plugins - if set, the result will contain details about the loaded plugins per node
* modules - details about the modules used

## Elasticsearch Event Example

```json
{
  ...
  "result": {
    "data": {
      "cluster_name": "eamon-database",
      "node_name": "VxD8WziwSeqcZjf7B5Eh8A",
      "name": "Vagabond",
      "transport_address": "XXX.XXX.XXX.XXX:9300",
      "host": "XXX.XXX.XXX.XXX",
      "ip": "XXX.XXX.XXX.XXX",
      "version": "2.3.3",
      "build": "218bdf1",
      "http_address": "XXX.XXX.XXX.XXX:9200",
      "settings": {
        "client": {
          "type": "node"
        },
        "name": "Vagabond",
        "path": {
          "logs": "/usr/local/elasticsearch/logs",
          "home": "/usr/local/elasticsearch"
        },
        "cluster": {
          "name": "eamon-database"
        },
        "cloud": {
          "aws": {
            "region": "us-east-1"
          }
        },
        "config": {
          "ignore_system_properties": "true"
        },
        "discovery": {
          "type": "ec2"
        },
        "network": {
          "host": "0.0.0.0"
        },
        "foreground": "false"
      },
      "os": {
        "refresh_interval_in_millis": 1000,
        "name": "Linux",
        "arch": "amd64",
        "version": "3.13.0-48-generic",
        "available_processors": 2,
        "allocated_processors": 2
      },
      "process": {
        "refresh_interval_in_millis": 1000,
        "id": 1930,
        "mlockall": false
      },
      "jvm": {
        "pid": 1930,
        "version": "1.7.0_101",
        "vm_name": "OpenJDK 64-Bit Server VM",
        "vm_version": "24.95-b01",
        "vm_vendor": "Oracle Corporation",
        "start_time_in_millis": 1466264171719,
        "mem": {
          "heap_init_in_bytes": 268435456,
          "heap_max_in_bytes": 1056309248,
          "non_heap_init_in_bytes": 24313856,
          "non_heap_max_in_bytes": 224395264,
          "direct_max_in_bytes": 1056309248
        },
        "gc_collectors": [
          "ParNew",
          "ConcurrentMarkSweep"
        ],
        "memory_pools": [
          "Code Cache",
          "Par Eden Space",
          "Par Survivor Space",
          "CMS Old Gen",
          "CMS Perm Gen"
        ],
        "using_compressed_ordinary_object_pointers": "true"
      },
      "thread_pool": {
        "generic": {
          "type": "cached",
          "keep_alive": "30s",
          "queue_size": -1
        },
        "index": {
          "type": "fixed",
          "min": 2,
          "max": 2,
          "queue_size": 200
        },
        "fetch_shard_store": {
          "type": "scaling",
          "min": 1,
          "max": 4,
          "keep_alive": "5m",
          "queue_size": -1
        },
        "get": {
          "type": "fixed",
          "min": 2,
          "max": 2,
          "queue_size": 1000
        },
        "snapshot": {
          "type": "scaling",
          "min": 1,
          "max": 1,
          "keep_alive": "5m",
          "queue_size": -1
        },
        "force_merge": {
          "type": "fixed",
          "min": 1,
          "max": 1,
          "queue_size": -1
        },
        "suggest": {
          "type": "fixed",
          "min": 2,
          "max": 2,
          "queue_size": 1000
        },
        "bulk": {
          "type": "fixed",
          "min": 2,
          "max": 2,
          "queue_size": 50
        },
        "warmer": {
          "type": "scaling",
          "min": 1,
          "max": 1,
          "keep_alive": "5m",
          "queue_size": -1
        },
        "flush": {
          "type": "scaling",
          "min": 1,
          "max": 1,
          "keep_alive": "5m",
          "queue_size": -1
        },
        "search": {
          "type": "fixed",
          "min": 4,
          "max": 4,
          "queue_size": 1000
        },
        "fetch_shard_started": {
          "type": "scaling",
          "min": 1,
          "max": 4,
          "keep_alive": "5m",
          "queue_size": -1
        },
        "listener": {
          "type": "fixed",
          "min": 1,
          "max": 1,
          "queue_size": -1
        },
        "percolate": {
          "type": "fixed",
          "min": 2,
          "max": 2,
          "queue_size": 1000
        },
        "refresh": {
          "type": "scaling",
          "min": 1,
          "max": 1,
          "keep_alive": "5m",
          "queue_size": -1
        },
        "management": {
          "type": "scaling",
          "min": 1,
          "max": 5,
          "keep_alive": "5m",
          "queue_size": -1
        }
      },
      "transport": {
        "bound_address": [
          "[::]:9300"
        ],
        "publish_address": "XXX.XXX.XXX.XXX:9300",
        "profiles": {}
      },
      "http": {
        "bound_address": [
          "[::]:9200"
        ],
        "publish_address": "XXX.XXX.XXX.XXX:9200",
        "max_content_length_in_bytes": 104857600
      },
      "plugins": [
        {
          "name": "cloud-aws",
          "version": "2.3.3",
          "description": "The Amazon Web Service (AWS) Cloud plugin allows to use AWS API for the unicast discovery mechanism and add S3 repositories.",
          "jvm": true,
          "classname": "org.elasticsearch.plugin.cloud.aws.CloudAwsPlugin",
          "isolated": true,
          "site": false
        }
      ],
      "modules": [
        {
          "name": "lang-expression",
          "version": "2.3.3",
          "description": "Lucene expressions integration for Elasticsearch",
          "jvm": true,
          "classname": "org.elasticsearch.script.expression.ExpressionPlugin",
          "isolated": true,
          "site": false
        },
        ...
      ]
    }
  }
}
```
