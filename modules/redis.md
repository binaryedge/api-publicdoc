# Redis

Extract Redis detailed information.

## Redis Request Example

```
curl -v -L https://api.binaryedge.io/v1/tasks -d '{"type":"scan", "options":[{"targets":["X.X.X.X"], "ports":[{"port":6379, "protocol":"tcp", "modules":["redis"]}]}]}' -H "X-Token:<Token>"
```

## Schema

### Redis Event Schema

```json
{
  ...
  "result": {
      "data": {
        "redis_version": "string",
        "redis_git_sha1": "string",
        "redis_git_dirty": "string",
        "redis_build_id": "string",
        "redis_mode": "string",
        "os": "string",
        "arch_bits": "string",
        "multiplexing_api": "string",
        "gcc_version": "string",
        "process_id": "string",
        "run_id": "string",
        "tcp_port": "string",
        "uptime_in_seconds": "int",
        "uptime_in_days": "int",
        "hz": "string",
        "lru_clock": "string",
        "config_file": "string",
        "connected_clients": "int",
        "client_longest_output_list": "int",
        "client_biggest_input_buf": "int",
        "blocked_clients": "int",
        "used_memory": "int",
        "used_memory_human": "string",
        "used_memory_rss": "int",
        "used_memory_peak": "int",
        "used_memory_peak_human": "string",
        "used_memory_lua": "int",
        "mem_fragmentation_ratio": "float",
        "mem_allocator": "string",
        "loading": "string",
        "rdb_changes_since_last_save": "int",
        "rdb_bgsave_in_progress": "string",
        "rdb_last_save_time": "int",
        "rdb_last_bgsave_status": "string",
        "rdb_last_bgsave_time_sec": "int",
        "rdb_current_bgsave_time_sec": "int",
        "aof_enabled": "string",
        "aof_rewrite_in_progress": "string",
        "aof_rewrite_scheduled": "string",
        "aof_last_rewrite_time_sec": "string",
        "aof_current_rewrite_time_sec": "string",
        "aof_last_bgrewrite_status": "string",
        "aof_last_write_status": "string",
        "total_connections_received": "int",
        "total_commands_processed": "int",
        "instantaneous_ops_per_sec": "int",
        "total_net_input_bytes": "int",
        "total_net_output_bytes": "int",
        "instantaneous_input_kbps": "int",
        "instantaneous_output_kbps": "int",
        "rejected_connections": "int",
        "sync_full": "string",
        "sync_partial_ok": "string",
        "sync_partial_err": "string",
        "expired_keys": "int",
        "evicted_keys": "int",
        "keyspace_hits": "int",
        "keyspace_misses": "int",
        "pubsub_channels": "int",
        "pubsub_patterns": "int",
        "latest_fork_usec": "string",
        "role": "string",
        "connected_slaves": "int",
        "master_repl_offset": "string",
        "repl_backlog_active": "string",
        "repl_backlog_size": "int",
        "repl_backlog_first_byte_offset": "string",
        "repl_backlog_histlen": "string",
        "used_cpu_sys": "float",
        "used_cpu_user": "float",
        "used_cpu_sys_children": "float",
        "used_cpu_user_children": "float",
        "db0": {
          "avg_ttl": "int",
          "expires": "int",
          "keys": "int"
        },
        "versions": [
          "int"
        ]
      }
    }
  }
```

### Contents of the fields:

*Variables description from https://redis.io/commands/INFO*

**Server** - General information about the Redis server
  * redis_version - version of the redis server
  * redis_git_sha1 - Git SHA1
  * redis_git_dirty - Git dirty flag
  * redis_build_id - build ID of the build of redis in use
  * redis_mode - type of redis server
  * os - operative system
  * arch_bits - architecture (32 or 64 bits)
  * multiplexing_api - event loop mechanism used by Redis
  * gcc_version - version of the GCC compiler used to compile the Redis server
  * process_id - PID of the server process
  * run_id - random value identifying the Redis server (to be used by Sentinel and Cluster)
  * tcp_port - TCP/IP listen port
  * uptime_in_seconds - number of seconds since Redis server start
  * uptime_in_days - same value expressed in days
  * hz - redis expiration rate
  * lru_clock - clock incrementing every minute, for LRU management
  * config_file - full path of the configuration file

**Clients** - Client connections section
  * connected_clients - number of client connections (excluding connections from slaves)
  * client_longest_output_list - longest output list among current client connections
  * client_biggest_input_buf - biggest input buffer among current client connections
  * blocked_clients - number of clients pending on a blocking call (BLPOP, BRPOP, BRPOPLPUSH)

**Memory** - Memory consumption related information
  * used_memory - total number of bytes allocated by Redis using its allocator (either standard libc, jemalloc, or an alternative allocator such as tcmalloc
  * used_memory_human - human readable representation of previous value (used_memory in MB or GB)
  * used_memory_rss - number of bytes that Redis allocated as seen by the operating system (a.k.a resident set size). This is the number reported by tools such as top(1) and ps(1)
  * used_memory_peak - peak memory consumed by Redis (in bytes)
  * used_memory_peak_human - human readable representation of previous value (used_memory_peak in MB or GB)
  * used_memory_lua - number of bytes used by the Lua engine
  * mem_fragmentation_ratio - ratio between used_memory_rss and used_memory
  * mem_allocator - memory allocator, chosen at compile time

**Persistence** - RDB and AOF related information
  * loading - flag indicating if the load of a dump file is on-going
  * rdb_changes_since_last_save - number of changes since the last dump
  * rdb_bgsave_in_progress - flag indicating a RDB save is on-going
  * rdb_last_save_time - epoch-based timestamp of last successful RDB save
  * rdb_last_bgsave_status - status of the last RDB save operation
  * rdb_last_bgsave_time_sec - duration of the last RDB save operation in seconds
  * rdb_current_bgsave_time_sec - duration of the on-going RDB save operation if any
  * aof_enabled - flag indicating AOF logging is activated
  * aof_rewrite_in_progress - flag indicating a AOF rewrite operation is on-going
  * aof_rewrite_scheduled - flag indicating an AOF rewrite operation will be scheduled once the on-going RDB save is complete.
  * aof_last_rewrite_time_sec - duration of the last AOF rewrite operation in seconds
  * aof_current_rewrite_time_sec - duration of the on-going AOF rewrite operation if any
  * aof_last_bgrewrite_status - status of the last AOF rewrite operation
  * aof_last_write_status - status of the last AOF write operation

**Stats** - General statistics
  * total_connections_received - total number of connections accepted by the server
  * total_commands_processed - total number of commands processed by the server
  * instantaneous_ops_per_sec - number of commands processed per second
  * total_net_input_bytes - total number of bytes inputted
  * total_net_output_bytes - total number of bytes outputted
  * instantaneous_input_kbps - total inbound traffic in kilobits per second
  * instantaneous_output_kbps - total outbound traffic in kilobits per second
  * rejected_connections - number of connections rejected because of maxclients limit
  * sync_full - count of the number times slaves have fully synchronized with this master
  * sync_partial_ok - count of the number of times partial syncs have completed
  * sync_partial_err - count of the number of times partial syncs have failed to complete
  * expired_keys - total number of key expiration events
  * evicted_keys - number of evicted keys due to maxmemory limit
  * keyspace_hits - number of successful lookup of keys in the main dictionary
  * keyspace_misses - number of failed lookup of keys in the main dictionary
  * pubsub_channels - global number of pub/sub channels with client subscriptions
  * pubsub_patterns - global number of pub/sub pattern with client subscriptions
  * latest_fork_usec - duration of the latest fork operation in microseconds

**Replication** - Master/slave replication information
  * role - value is "master" if the instance is slave of no one, or "slave" if the instance is enslaved to a master. Note that a slave can be master of another slave (daisy chaining)  
  * connected_slaves - number of connected slaves
  * master_repl_offset - target offset of master dataset
  * repl_backlog_active - backlog active?
  * repl_backlog_size - size of the backlog
  * repl_backlog_first_byte_offset -  slave replication backlog offset
  * repl_backlog_histlen - number of messages in the replication backlog

**CPU** - CPU consumption statistics
  * used_cpu_sys - system CPU consumed by the Redis server
  * used_cpu_user - user CPU consumed by the Redis server
  * used_cpu_sys_children - system CPU consumed by the background processes
  * used_cpu_user_children - user CPU consumed by the background processes

**Keyspace** - Database related statistics
  * dbX: database name/ number
    * avg_ttl - the average TTL of the keys that have an expiration set
    * expires - number of keys with an expiration set
    * keys - total number of keys in the database

  * versions - redis version split by major, intermediate and minor.

## Redis Event Example

```json
{
  ...
  "result": {
      "data": {
        "redis_version": "2.8.18",
        "redis_git_sha1": "00000000",
        "redis_git_dirty": "0",
        "redis_build_id": "96cd9986d619c84f",
        "redis_mode": "standalone",
        "os": "Linux 3.10.0-123.el7.x86_64 x86_64",
        "arch_bits": "64",
        "multiplexing_api": "epoll",
        "gcc_version": "4.8.2",
        "process_id": "1122",
        "run_id": "7f82d087bc6c008432cc5b6a553fe8e42741692d",
        "tcp_port": "6379",
        "uptime_in_seconds": 1808861,
        "uptime_in_days": 20,
        "hz": "10",
        "lru_clock": "4066725",
        "config_file": "/etc/redis/6379.conf",
        "connected_clients": 66,
        "client_longest_output_list": 0,
        "client_biggest_input_buf": 0,
        "blocked_clients": 0,
        "used_memory": 2722328,
        "used_memory_human": "2.60M",
        "used_memory_rss": 3207168,
        "used_memory_peak": 4598080,
        "used_memory_peak_human": "4.39M",
        "used_memory_lua": 35840,
        "mem_fragmentation_ratio": 1.18,
        "mem_allocator": "jemalloc-3.6.0",
        "loading": "0",
        "rdb_changes_since_last_save": 0,
        "rdb_bgsave_in_progress": "0",
        "rdb_last_save_time": 1480447501,
        "rdb_last_bgsave_status": "ok",
        "rdb_last_bgsave_time_sec": 0,
        "rdb_current_bgsave_time_sec": -1,
        "aof_enabled": "0",
        "aof_rewrite_in_progress": "0",
        "aof_rewrite_scheduled": "0",
        "aof_last_rewrite_time_sec": "-1",
        "aof_current_rewrite_time_sec": "-1",
        "aof_last_bgrewrite_status": "ok",
        "aof_last_write_status": "ok",
        "total_connections_received": 980589,
        "total_commands_processed": 3203816,
        "instantaneous_ops_per_sec": 0,
        "total_net_input_bytes": 3949484738,
        "total_net_output_bytes": 9016490032,
        "instantaneous_input_kbps": 0,
        "instantaneous_output_kbps": 0,
        "rejected_connections": 0,
        "sync_full": "0",
        "sync_partial_ok": "0",
        "sync_partial_err": "0",
        "expired_keys": 4969,
        "evicted_keys": 0,
        "keyspace_hits": 399875,
        "keyspace_misses": 25050,
        "pubsub_channels": 0,
        "pubsub_patterns": 0,
        "latest_fork_usec": "239",
        "role": "master",
        "connected_slaves": 0,
        "master_repl_offset": "0",
        "repl_backlog_active": "0",
        "repl_backlog_size": 1048576,
        "repl_backlog_first_byte_offset": "0",
        "repl_backlog_histlen": "0",
        "used_cpu_sys": 554.66,
        "used_cpu_user": 358.41,
        "used_cpu_sys_children": 1.67,
        "used_cpu_user_children": 3.86,
        "db0": {
          "avg_ttl": 552142683,
          "expires": 2,
          "keys": 80
        },
        "versions": [
          2,
          8,
          18
        ]
      }
    }
  }

```
