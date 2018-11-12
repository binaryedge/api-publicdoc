# Elasticsearch

Extract Elasticsearch detailed information.

## Elasticsearch Request Example

```
curl -v -L https://api.binaryedge.io/v1/tasks -d '{"type":"scan", "options":[{"targets":["X.X.X.X"], "ports":[{"port":9200, "protocol":"tcp", "modules":["elasticsearch"]}]}]}' -H "X-Token:<Token>"
```

## Schema

  Note: You can see the version on "result.data.version"

### [Version 5.X] Elasticsearch Event Schema 

```json
{
  ...
  "result": {
    "data": {
      "cluster_name": "string",
      "cluster_nodes": "int",
      "node_name": "string",
      "indices": [
        {
          "index_name": "string",
          "docs": "int",
          "size_in_bytes": "int"
        }
      ],
      "name": "string",
      "transport_address": "string",
      "host": "string",
      "ip": "string",
      "version": "string",
      "build_hash": "string",
      "total_indexing_buffer": "int",
      "roles": [ 
        "string" 
      ],
      "settings": {
        "pidfile": "string",
        "client": {
          "type": "string"
        },
        "default": {
          "path": {
            "data": "string",
            "logs": "string",
            "conf": "string"
          }
        },
        "node":{
          "name": "string"
        },
        "path": {
          "logs": "string",
          "home": "string"
        },
        "cluster": {
          "name": "string"
        },
        "http": {
          "type": {
            "default": "string"
          },
          "port": "int"
        },
        "transport": {
          "type": {
            "default": "string"
          }
        },
        "network": {
          "host": "string"
        }
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
        "using_compressed_ordinary_object_pointers": "string",
        "input_arguments": [
          "string"
        ]
      },
      "ingest": {
        "processors":[
          {
            "type": "string"
          }
        ]
      },
      "thread_pool": {
        "generic": {
          "type": "string",
          "min": "int",
          "max": "int",
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
          "description": "string",
          "site": "boolean",
          "jvm": "boolean",
          "url": "string"
        },
        ...
      ],
      "modules": [
        {
          "name": "string",
          "version": "string",
          "description": "string",
          "classname": "string",
          "has_native_controller": "boolean",
        },
        ...
      ]
    }
  }
}
```

### [Version 2.X] Elasticsearch Event Schema

```json
{
  ...
  "result": {
    "data": {
      "cluster_name": "string",
      "cluster_nodes": "int",
      "node_name": "string",
      "indices": [
        {
          "index_name": "string",
          "docs": "int",
          "size_in_bytes": "int"
        }
      ],
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
* cluster_nodes - number of nodes in the cluster
* indices - list of indices currently stored in the cluster
    * index_name - name of the index
    * docs - number of documents in the index
    * size_in_bytes - size of the index
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
  "result": {
    "data": {
      "indices": [
        {
          "size_in_bytes": 4783,
          "docs": 1,
          "index_name": "readme"
        },
        {
          "size_in_bytes": 74938880,
          "docs": 20842,
          "index_name": "atom"
        }
      ],
      "plugins": [],
      "http": {
        "max_content_length_in_bytes": 104857600,
        "publish_address": "inet[/XXX.XXX.XXX.XXX:9200]",
        "bound_address": "inet[/0:0:0:0:0:0:0:0:9200]"
      },
      "transport": {
        "profiles": {},
        "publish_address": "inet[/XXX.XXX.XXX.XXX:9300]",
        "bound_address": "inet[/0:0:0:0:0:0:0:0:9300]"
      },
      "version": "1.7.6",
      "ip": "127.0.1.1",
      "host": "gir5",
      "transport_address": "inet[/XXX.XXX.XXX.XXX:9300]",
      "name": "Karolina Dean",
      "node_name": "ZWxo6SmoTGKxzsW1ArD9XQ",
      "cluster_nodes": 1,
      "cluster_name": "elasticsearch",
      "build": "c730b59",
      "http_address": "inet[/XXX.XXX.XXX.XXX:9200]",
      "settings": {
        "config": "/etc/elasticsearch/elasticsearch.yml",
        "config.ignore_system_properties": "true",
        "foreground": "yes",
        "client": {
          "type": "node"
        },
        "name": "Karolina Dean",
        "cluster": {
          "name": "elasticsearch"
        },
        "path": {
          "home": "/usr/share/elasticsearch",
          "logs": "/var/log/elasticsearch",
          "data": "/var/lib/elasticsearch",
          "conf": "/etc/elasticsearch"
        },
        "pidfile": "/var/run/elasticsearch/elasticsearch.pid"
      },
      "os": {
        "swap": {
          "total_in_bytes": 4292866048
        },
        "mem": {
          "total_in_bytes": 5200592896
        },
        "cpu": {
          "cache_size_in_bytes": 6144,
          "cores_per_socket": 1,
          "total_sockets": 1,
          "total_cores": 1,
          "mhz": 2327,
          "model": "Xeon",
          "vendor": "Intel"
        },
        "available_processors": 1,
        "refresh_interval_in_millis": 1000
      },
      "process": {
        "mlockall": false,
        "max_file_descriptors": 65535,
        "id": 3501,
        "refresh_interval_in_millis": 1000
      },
      "jvm": {
        "memory_pools": [
          "Code Cache",
          "Metaspace",
          "Compressed Class Space",
          "Par Eden Space",
          "Par Survivor Space",
          "CMS Old Gen"
        ],
        "pid": 3501,
        "version": "1.8.0_181",
        "vm_name": "OpenJDK 64-Bit Server VM",
        "vm_version": "25.181-b13",
        "vm_vendor": "Oracle Corporation",
        "start_time_in_millis": 1541638803839,
        "mem": {
          "direct_max_in_bytes": 1065025536,
          "non_heap_max_in_bytes": 0,
          "non_heap_init_in_bytes": 2555904,
          "heap_max_in_bytes": 1065025536,
          "heap_init_in_bytes": 268435456
        },
        "gc_collectors": [
          "ParNew",
          "ConcurrentMarkSweep"
        ]
      },
      "thread_pool": {
        "snapshot": {
          "queue_size": -1,
          "keep_alive": "5m",
          "max": 1,
          "min": 1,
          "type": "scaling"
        },
        "warmer": {
          "queue_size": -1,
          "keep_alive": "5m",
          "max": 1,
          "min": 1,
          "type": "scaling"
        },
        "generic": {
          "queue_size": -1,
          "keep_alive": "30s",
          "type": "cached"
        },
        "suggest": {
          "queue_size": "1k",
          "max": 1,
          "min": 1,
          "type": "fixed"
        },
        "refresh": {
          "queue_size": -1,
          "keep_alive": "5m",
          "max": 1,
          "min": 1,
          "type": "scaling"
        },
        "index": {
          "queue_size": "200",
          "max": 1,
          "min": 1,
          "type": "fixed"
        },
        "listener": {
          "queue_size": -1,
          "max": 1,
          "min": 1,
          "type": "fixed"
        },
        "fetch_shard_started": {
          "queue_size": -1,
          "keep_alive": "5m",
          "max": 2,
          "min": 1,
          "type": "scaling"
        },
        "percolate": {
          "queue_size": "1k",
          "max": 1,
          "min": 1,
          "type": "fixed"
        },
        "search": {
          "queue_size": "1k",
          "max": 2,
          "min": 2,
          "type": "fixed"
        },
        "flush": {
          "queue_size": -1,
          "keep_alive": "5m",
          "max": 1,
          "min": 1,
          "type": "scaling"
        },
        "optimize": {
          "queue_size": -1,
          "max": 1,
          "min": 1,
          "type": "fixed"
        },
        "fetch_shard_store": {
          "queue_size": -1,
          "keep_alive": "5m",
          "max": 2,
          "min": 1,
          "type": "scaling"
        },
        "management": {
          "queue_size": -1,
          "keep_alive": "5m",
          "max": 5,
          "min": 1,
          "type": "scaling"
        },
        "get": {
          "queue_size": "1k",
          "max": 1,
          "min": 1,
          "type": "fixed"
        },
        "merge": {
          "queue_size": -1,
          "keep_alive": "5m",
          "max": 1,
          "min": 1,
          "type": "scaling"
        },
        "bulk": {
          "queue_size": "50",
          "max": 1,
          "min": 1,
          "type": "fixed"
        }
      },
      "network": {
        "primary_interface": {
          "mac_address": "00:50:56:85:06:2B",
          "name": "eth0",
          "address": "10.50.0.120"
        },
        "refresh_interval_in_millis": 5000
      }
    }
  },
  ...
}
```
