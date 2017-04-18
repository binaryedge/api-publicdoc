# MongoDB

Extract MongoDB detailed information.

## MongoDB Request Example

```
curl -v -L https://api.binaryedge.io/v1/tasks -d '{"type":"scan", "options":[{"targets":["X.X.X.X"], "ports":[{"port":27017, "protocol":"tcp", "modules":["mongodb"]}]}]}' -H "X-Token:<Token>"
```

## Schema

### MongoDB Event Schema

The event does not always follow the same schema; it changes according to the MongoDB version in use. This event schema contains all the possible options.

```json
{
  ...
  "result": {
    "data": {
      "ping": {
        "ok": "int"
      },
      "serverInfo": {
        "version": "string",
        "gitVersion": "string",
        "targetMinOS": "string",
        "modules": ["string"],
        "allocator": "string",
        "loaderFlags": "string",
        "compilerFlags": "string",
        "allocator": "string",
        "javascriptEngine": "string",
        "OpenSSLVersion": "string",
        "sysInfo": "string",
        "versionArray": [
          "int"
        ],
        "openssl": {
          "running": "string",
          "compiled": "string"
        },
        "buildEnvironment": {
          "distmod": "string",
          "distarch": "string",
          "cc": "string",
          "ccflags": "string",
          "cxx": "string",
          "cxxflags": "string",
          "linkflags": "string",
          "target_arch": "string",
          "target_os": "string"
        },
        "bits": "int",
        "debug": "boolean",
        "maxBsonObjectSize": "int",
        "storageEngines": [
          "string"
        ],
        "ok": "int"
      },
      "listDatabases": {
        "databases": [
          {
            "name": "string",
            "sizeOnDisk": "int",
            "empty": "boolean",
            "stats": {
              "db": "string",
              "collections": "int",
              "objects": "int",
              "avgObjSize": "int",
              "dataSize": "int",
              "storageSize": "int",
              "numExtents": "int",
              "indexes": "int",
              "indexSize": "int",
              "fileSize": "int",
              "nsSizeMB": "int",
              "extentFreeList": {
                "num": "int",
                "totalSize": "int"
              },
              "dataFileVersion": {
                "major": "int",
                "minor": "int"
              },
              "ok": "int"
            },
            "collections": [
              {
                "name": "string",
                "options": {}
              }
            ]
          },
          ...
        ],
        "totalSize": "int",
        "ok": "int"
      }
    },
  }
}
```


### Contents of the fields:

*Variables description from https://docs.mongodb.com/manual/*

* serverInfo
  * version - a string that conveys version information about the mongod instance
  * gitVersion - the commit identifier that identifies the state of the code used to build the mongod.
  * OpenSSLVersion - an embedded document describing the version of OpenSSL that mongod was built with, as well as the version of OpenSSL that mongod is currently using.
  * sysInfo - a string that holds information about the operating system, hostname, kernel, date, and Boost version used to compile the mongod. (Deprecated since version 3.2.)
  * versionArray - an array that conveys version information about the mongod instance
  * loaderFlags - the flags passed to the loader that loads the mongod
  * compilerFlags - the flags passed to the compiler that builds the mongod binary
  * allocator - the memory allocator that mongod uses. By default this is tcmalloc
  * javascriptEngine - A string that reports the JavaScript engine used in the mongod instance
  * bits - reflects the target processor architecture of the mongod binary
  * debug - boolean. true when built with debugging options.
  * maxBsonObjectSize - reports the Maximum BSON Document Size
  * targetMinOS - minimum version of the OS where this build of mongodb runs
  * modules - a list of add-on modules that mongod was built with
  * openSSL - an embedded document describing the version of OpenSSL that mongod was built with, as well as the version of OpenSSL that mongod is currently using. Note: this field contains similar information as the OpenSSLVersion field, whether one or the other appears on the results, depends on the mongodb version
    * running - version of openSSL running
    * compiled - version of openSSL compiled
  * buildEnvironment - an embedded document containing various debugging information about the mongod build environment
    * distMod
    * distarch
    * cc
    * ccflags
    * cxx
    * cxxflags
    * linkflags
    * target_arch
    * target_os
  * storageEngines - list of storage engines being zsed
  * ok - this value determines the success of the serverInfo commands. 1 indicates success

* listDatabases -
  * database - array of documents, one document for each database
    * name - name of the database
    * sizeOnDisk -  total size of the database file on disk in bytes
    * empty - this field specifying whether the database has any data
    * stats - returns a variety of storage statistics for a given collection
      * db - name of the database
      * collections - number of collections in the database
      * objects - number of documents in the database
      * avgObjSize - the average size of an object in the collection
      * dataSize - total size of all documents stored in this database
      * storageSize - the total amount of storage allocated to this collection for document storage
      * numExtents - the total number of contiguously allocated data file regions.
      * indexes - the number of indexes on the collection
      * indexSize -  key and size of every existing index on the collection
      * fileSize - total size of storage files used for this database (represents the overall storage footprint for this database on disk)
      * nsSizeMB - the total size of the namespace files
      * extentFreeList - free space
        * num - number of extents in the freelist
        * totalSize -  total size of the extents on the freelist
      * dataFileVersion - document that contains information about the on-disk format of the data files for the database.
        * major - the major version number for the on-disk format of the data files for the database
        * minor - the minor version number for the on-disk format of the data files for the database
    * collections - list of collections (includes their name and options)
      * name - name of the collection
      * options
        * capped - True if it's a fixed-sized collection that automatically overwrites its oldest entries when it reaches its maximum size
        * size - maximum size of the capped collection in bytes
        * autoIndexId - creates an index automatically if it's "true"
    * totalSize - sum of all the sizeOnDisk fields.
    * totalSizeMb - totalSize in megabytes
    * ok - this value determines the success of the listDatabases commands. 1 indicates success


## MongoDB Event Examples

#### Example 1

```json
{
  ...
  "result": {
    "data": {
      "ping": {
        "ok": 1
      },
      "serverInfo": {
        "version": "3.2.9",
        "gitVersion": "22ec9e93b40c85fc7cae7d56e7d6a02fd811088c",
        "targetMinOS": "Windows 7/Windows Server 2008 R2",
        "modules": [],
        "allocator": "tcmalloc",
        "javascriptEngine": "mozjs",
        "sysInfo": "deprecated",
        "versionArray": [
          3,
          2,
          9,
          0
        ],
        "openssl": {
          "running": "OpenSSL 1.0.1p-fips 9 Jul 2015",
          "compiled": "OpenSSL 1.0.1p-fips 9 Jul 2015"
        },
        "buildEnvironment": {
          "distmod": "2008plus-ssl",
          "distarch": "x86_64",
          "cc": "cl: Microsoft (R) C/C++ Optimizing Compiler Version 18.00.31101 for x64",
          "ccflags": "/nologo /EHsc /W3 /wd4355 /wd4800 /wd4267 /wd4244 /wd4290 /wd4068 /wd4351 /we4013 /we4099 /we4930 /Z7 /errorReport:none /MD /O2 /Oy- /Gw /Gy /Zc:inline",
          "cxx": "cl: Microsoft (R) C/C++ Optimizing Compiler Version 18.00.31101 for x64",
          "cxxflags": "/TP",
          "linkflags": "/nologo /DEBUG /INCREMENTAL:NO /LARGEADDRESSAWARE /OPT:REF",
          "target_arch": "x86_64",
          "target_os": "windows"
        },
        "bits": 64,
        "debug": false,
        "maxBsonObjectSize": 16777216,
        "storageEngines": [
          "devnull",
          "ephemeralForTest",
          "mmapv1",
          "wiredTiger"
        ],
        "ok": 1
      },
      "listDatabases": {
        "databases": [
          {
            "name": "fulltext",
            "sizeOnDisk": 49152,
            "empty": false,
            "stats": {
              "db": "fulltext",
              "collections": 1,
              "objects": 1,
              "avgObjSize": 37,
              "dataSize": 37,
              "storageSize": 24576,
              "numExtents": 0,
              "indexes": 1,
              "indexSize": 24576,
              "ok": 1
            },
            "collections": [
              {
                "name": "fulltext",
                "options": {}
              }
            ]
          },
          ...
        ],
        "totalSize": 76075884544,
        "ok": 1
      }
    },
  }
}
```

#### Example 2:

```json
{
  ...
  "result": {
  "data": {
    "ping": {
      "ok": 1
    },
    "serverInfo": {
      "version": "3.0.6",
      "gitVersion": "1ef45a23a4c5e3480ac919b28afcba3c615488f2",
      "OpenSSLVersion": "OpenSSL 1.0.0-fips 29 Mar 2010",
      "sysInfo": "Linux ip-10-158-149-195 3.4.43-43.43.amzn1.x86_64 #1 SMP Mon May 6 18:04:41 UTC 2013 x86_64 BOOST_LIB_VERSION=1_49",
      "versionArray": [
        3,
        0,
        6,
        0
      ],
      "loaderFlags": "",
      "compilerFlags": "-Wnon-virtual-dtor -Woverloaded-virtual -std=c++11 -fPIC -fno-strict-aliasing -ggdb -pthread -Wall -Wsign-compare -Wno-unknown-pragmas -Winvalid-pch -pipe -Werror -O3 -Wno-unused-local-typedefs -Wno-unused-function -Wno-deprecated-declarations -Wno-unused-but-set-variable -Wno-missing-braces -fno-builtin-memcmp -std=c99",
      "allocator": "tcmalloc",
      "javascriptEngine": "V8",
      "bits": 64,
      "debug": false,
      "maxBsonObjectSize": 16777216,
      "ok": 1
    },
    "listDatabases": {
      "databases": [
        {
          "name": "tqchataction",
          "sizeOnDisk": 83886080,
          "empty": false,
          "stats": {
            "db": "tqchataction",
            "collections": 3,
            "objects": 8702,
            "avgObjSize": 858.502413238336,
            "dataSize": 7470688,
            "storageSize": 11194368,
            "numExtents": 8,
            "indexes": 1,
            "indexSize": 294336,
            "fileSize": 67108864,
            "nsSizeMB": 16,
            "extentFreeList": {
              "num": 0,
              "totalSize": 0
            },
            "dataFileVersion": {
              "major": 4,
              "minor": 22
            },
            "ok": 1
          },
          "collections": [
            {
              "name": "chat_xw_tb",
              "options": {}
            },
            ...
          ]
        }
        ...
      ]
    }
  }
  }
}
```
