# HTTP

Extract HTTP information, e.g. HTTP headers, HTTP status codes, HTTP body, and redirects information. Follows up to 5 redirects.

## HTTP Request Example

```
curl -v -L https://api.binaryedge.io/v1/tasks  -d  '{"type":"grab", "options":[{"targets":["X.X.X.X"], "ports":[{"port":80,"protocol":"tcp","modules": ["http"]}]}]}' -H 'X-Token:<Token>'
```

## Schema

### HTTP Event Schema

```
{
  ...
  "result": {
    "data": {
      "request": {
        "url": "string",
        "headers": {
          "User-Agent": "string"
        }
      },
      "response": {
      	"body": "string",
        "httpVersion": "string",
        "statusCode": int,
        "statusMessage": "string",
        "headers": {<found headers>},
        "href": "string",
        "redirects": [{
          "statusCode": int,
          "redirectUri": "string"
        }, {
          "statusCode": int,
          "redirectUri": "string"
        }]
      }
    }
  }
}
```

### Contents of the fields:

  * request - Request made by the module
  	* url - Requested URL
  	* headers - Headers used in the request
  * response - Response from server
	* body - HTML body response
	* httpVersion - HTTP version
	* statusCode - HTTP response status code
	* statusMeessage - HTTP status message
	* headers - HTTP headers
	* href - Final href found (after redirects if the case)
	* redirects - List of redirects followed
		* statusCode - Redirect status code
		* redirectUri - Redirect location
	
## HTTP Event Example
The HTTP module request:

```
curl -v -L https://api.binaryedge.io/v1/tasks  -d  '{"type":"grab", "options":[{"targets":["2a03:2880:2130:cf24:face:b00c::25de"], "ports":[{"port":80,"protocol":"tcp","modules": ["http"]}]}]}' -H 'X-Token:<Token>'
```

Would generate a output similar to:

```
{
  ...
  "result": {
    "data": {
      "request": {
        "url": "http://[2a03:2880:2130:cf24:face:b00c::25de]/",
        "headers": {
          "User-Agent": "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36"
        }
      },
      "response": {
      	"body": <HTML body>,
        "httpVersion": "1.1",
        "statusCode": 200,
        "statusMessage": "OK",
        "headers": {
          "p3p": "CP=\"Facebook does not have a P3P policy. Learn why here: http://fb.me/p3p\"",
          "x-frame-options": "DENY",
          "x-xss-protection": "0",
          "x-content-type-options": "nosniff",
          "strict-transport-security": "max-age=15552000; preload",
          "public-key-pins-report-only": "max-age=500; pin-sha256=\"WoiWRyIOVNa9ihaBciRSC7XHjliYS9VwUGOIud4PB18=\"; pin-sha256=\"r/mIkG3eEpVdm+u/ko/cwxzOMo1bk4TyHIlByibiA5E=\"; pin-sha256=\"q4PO2G2cbkZhZ82+JgmRUyGMoAeozA+BSXVXQWB8XWQ=\"; report-uri=\"http://reports.fb.com/hpkp/\"",
          "pragma": "no-cache",
          "content-security-policy": "default-src * data: blob:;script-src *.facebook.com *.fbcdn.net *.facebook.net *.google-analytics.com *.virtualearth.net *.google.com 127.0.0.1:* *.spotilocal.com:* 'unsafe-inline' 'unsafe-eval' fbstatic-a.akamaihd.net fbcdn-static-b-a.akamaihd.net *.atlassolutions.com blob: chrome-extension://lifbcibllhkdhoafpjfnlhfpfgnpldfl;style-src * 'unsafe-inline' data:;connect-src *.facebook.com *.fbcdn.net *.facebook.net *.spotilocal.com:* *.akamaihd.net wss://*.facebook.com:* https://fb.scanandcleanlocal.com:* *.atlassolutions.com attachment.fbsbx.com ws://localhost:* blob: 127.0.0.1:*;",
          "cache-control": "private, no-cache, no-store, must-revalidate",
          "expires": "Sat, 01 Jan 2000 00:00:00 GMT",
          "set-cookie": ["reg_ext_ref=deleted; expires=Thu, 01-Jan-1970 00:00:01 GMT; Max-Age=0; path=/; domain=.facebook.com; httponly"],
          "vary": "Accept-Encoding",
          "content-type": "text/html",
          "x-fb-debug": "vyFX+XU89sgCLeF4ToVyD9rJRB/V2K7q64VSFdmtcY9EpU/dlIBXHsswTu50OQ6n27xAXuRf5RpXT7ZZlioKsA==",
          "date": "Mon, 18 Apr 2016 17:10:20 GMT",
          "connection": "close"
        },
        "href": "https://www.facebook.com/",
        "redirects": [{
          "statusCode": 301,
          "redirectUri": "http://www.facebook.com/"
        }, {
          "statusCode": 302,
          "redirectUri": "https://www.facebook.com/"
        }]
      }
    }
  }
}
```