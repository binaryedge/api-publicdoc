# Memcached

Extract Memcached detailed information.

## Memcached Request Example

```
curl -v -L https://api.binaryedge.io/v1/tasks -d '{"type":"scan", "options":[{"targets":["X.X.X.X"], "ports":[{"port":11211, "protocol":"tcp", "modules":["memcached"]}]}]}' -H "X-Token:<Token>"
```

## Schema

### Memcached Event Schema

```json
{
  ...
  "result": {
    "data": {
      "server": "string",
      "pid": "int",
      "uptime": "int",
      "time": "int",
      "version": "string",
      "pointer_size": "int",
      "curr_connections": "int",
      "total_connections": "int",
      "connection_structures": "int",
      "cmd_get": "int",
      "cmd_set": "int",
      "cmd_flush": "int",
      "get_hits": "int",
      "get_misses": "int",
      "delete_misses": "int",
      "delete_hits": "int",
      "incr_misses": "int",
      "incr_hits": "int",
      "decr_misses": "int",
      "decr_hits": "int",
      "cas_misses": "int",
      "cas_hits": "int",
      "cas_badval": "int",
      "auth_cmds": "int",
      "auth_errors": "int",
      "bytes_read": "int",
      "bytes_written": "int",
      "limit_maxbytes": "int",
      "accepting_conns": "int",
      "listen_disabled_num": "int",
      "threads": "int",
      "conn_yields": "int",
      "bytes": "int",
      "curr_items": "int",
      "total_items": "int",
      "evictions": "int"
    }
  }
}
```


### Contents of the fields:

*Variables description from http://www.pal-blog.de/entwicklung/perl/memcached-statistics-stats-command.html*

* server - ip:port
* pid - current process ID of the Memcached task
* uptime - number of seconds the Memcached server has been running since last restart
* time - current unix timestamp of the Memcached's server
* version - version number of the server
* pointer_size - number of bits of the hostsystem, may show "32" instead of "64" if the running Memcached binary was compiled for 32 bit environments and is running on a 64 bit system
* curr_connections - number of open connections to this Memcached server, should be the same value on all servers during normal operation
* total_connections - number of successful connect attempts to this server since it has been started. Roughly $number_of_connections_per_task * $number_of_webserver_tasks * $number_of_webserver_restarts
* connection_structures - number of internal connection handles currently held by the server. May be used as some kind of "maximum parallel connection count" but the server may destroy connection structures (don't know if he ever does) or prepare some without having actual connections for them (also don't know if he does). 42 maximum connections and 34 current connections (curr_connections) sounds reasonable, the live servers also have about 10% more connection_structures than curr_connections
* cmd_get - number of "get" commands received since server startup not counting if they were successful or not
* cmd_set - number of "set" commands serviced since startup
* cmd_flush - the "flush_all" command clears the whole cache and shouldn't be used during normal operation
* get_hits - number of successful "get" commands (cache hits) since startup, divide them by the "cmd_get" value to get the cache hitrate
* get_misses - number of failed "get" requests because nothing was cached for this key or the cached value was too old
* delete_misses - number of "delete" commands for keys not existing within the cache
* delete_hits - stored keys may be deleted using the "delete" command, this system doesn't delete cached data itself, but it's using the Memcached to avoid recaching-races and the race keys are deleted once the race is over and fresh content has been cached
* incr_misses - number of failed "incr" commands
* incr_hits - number of successful "incr" commands processed. "incr" is a replace adding 1 to the stored value and failing if no value is stored
* decr_misses - "decr" command calls to undefined keys
* decr_hits - the "decr" command decreases a stored (integer) value by 1. A "hit" is a "decr" call to an existing key.
* cas_misses - "cas" calls fail if the value has been changed since it was requested from the cache. We're currently not using "cas" at all, so all three cas values are zero
* cas_hits - number of successful "cas" commands
* cas_badval - the "cas" command is some kind of Memcached's way to avoid locking. "cas" calls with bad identifier are counted in this stats key
* auth_cmds - number of authentication commands processed by the server - if you use authentication within your installation. The default is IP (routing) level security which speeds up the actual Memcached usage by removing the authentication requirement
* auth_errors - number of failed authentication tries of clients
* bytes_read - total number of bytes received from the network by this server
* bytes_written - total number of bytes send to the network by this server
* limit_maxbytes - maximum configured cache size (set on the command line while starting the memcached server), look at the "bytes" value for the actual usage
* accepting_conns - the Memcached server is currently accepting new connections.
* listen_disabled_num - number of denied connection attempts because memcached reached it's configured connection limit
* threads - number of threads used by the current Memcached server process
* conn_yields - memcached has a configurable maximum number of requests per event (-R command line argument), this counter shows the number of times any client hit this limit
* bytes - number of bytes currently used for caching items
* curr_items - number of items currently in this server's cache
* total_items - number of items stored ever stored on this server
* evictions - number of objects removed from the cache to free up memory for new items because Memcached reached it's maximum memory setting (limit_maxbytes)

## Memcached Event Example

```json
{
  ...
  "result": {
    "data": {
      "server": "XXX.XXX.XXX.XXX:11211",
      "pid": 1908,
      "uptime": 3056278089,
      "time": 240034076,
      "version": "1.4.4-14-g9c660c0",
      "pointer_size": 64,
      "curr_connections": 10,
      "total_connections": 115,
      "connection_structures": 31,
      "cmd_get": 2277,
      "cmd_set": 1343,
      "cmd_flush": 0,
      "get_hits": 1990,
      "get_misses": 287,
      "delete_misses": 0,
      "delete_hits": 124,
      "incr_misses": 0,
      "incr_hits": 0,
      "decr_misses": 0,
      "decr_hits": 0,
      "cas_misses": 0,
      "cas_hits": 0,
      "cas_badval": 0,
      "auth_cmds": 0,
      "auth_errors": 0,
      "bytes_read": 17127516,
      "bytes_written": 21691976,
      "limit_maxbytes": 67108864,
      "accepting_conns": 1,
      "listen_disabled_num": 0,
      "threads": 4,
      "conn_yields": 0,
      "bytes": 1006527,
      "curr_items": 120,
      "total_items": 1343,
      "evictions": 0
    }
  }
}
```
