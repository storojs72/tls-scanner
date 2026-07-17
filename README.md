# TLS scanner

Basic scanner of TLS connections via BouncyCastle crypto-provider.

Tested only on MacOS currently.

## Prerequisites

You need to have JAVA installed. If not installed, try setting it via homebrew:

```
brew install openjdk
```

## Build

```
javac -cp "lib/*" -d out TlsTest.java
javac -cp "lib/*" -d out SupportedSuites.java
```

## Run

```
tls-scanner % java -cp "lib/*:out" TlsTest cloudflare.com
Connecting to cloudflare.com on port 443...
Handshake successful! Server certificate received.
HTTP/1.1 301 Moved Permanently
Date: Tue, 14 Jul 2026 18:30:49 GMT
Content-Type: text/html
Content-Length: 167
Connection: close
Cache-Control: max-age=3600
Expires: Tue, 14 Jul 2026 19:30:49 GMT
Location: https://www.cloudflare.com/
Set-Cookie: __cf_bm=paDw3IwOwV762L0i8CY7XU44JfEjwz4Sb1IJgu7oMcc-1784053849-1.0.1.1-3AwPuVnjd1WzNNaSK2pskDOUvjNBYN63TolZGnmq08fJHUyOohoOUvsfIaCICDsQ2ahvZ3oG4XYxttxOVmCYz2DG9IiaYKV5Aya5g2Kqtew; path=/; expires=Tue, 14-Jul-26 19:00:49 GMT; domain=.cloudflare.com; HttpOnly; Secure
Report-To: {"endpoints":[{"url":"https:\/\/a.nel.cloudflare.com\/report\/v4?s=e%2Fnx4FRshcwf8Bdj2nxnimKVmeWEtjsQhQfnIR5FfURgmfFbmilsdV%2BHO3yqpmSi%2BVk2zMoti68%2BsdWG8nFh3HYp26ne6x4nKS8voOykbpMr1TsEFID4R486YqlR9RmS"}],"group":"cf-nel","max_age":604800}
NEL: {"success_fraction":0,"report_to":"cf-nel","max_age":604800}
Strict-Transport-Security: max-age=15780000; includeSubDomains
Server: cloudflare
CF-RAY: a1b299cc682f5bab-VIE
alt-svc: h3=":443"; ma=86400

<html>
<head><title>301 Moved Permanently</title></head>
<body>
<center><h1>301 Moved Permanently</h1></center>
<hr><center>cloudflare</center>
</body>
</html>
tls-scanner %
```

```
tls-scanner % java -cp "lib/*:out" SupportedSuites github.com
Scanning github.com on port 443 across 326 cipher suites...
This may take a moment as we test suites individually...

========================================
 Scan Results for: github.com
========================================
The server accepted the following 3 suite(s):
 - TLS_AES_128_GCM_SHA256 (0x1301)
 - TLS_AES_256_GCM_SHA384 (0x1302)
 - TLS_CHACHA20_POLY1305_SHA256 (0x1303)
========================================
tls-scanner %
```

It is also possible to use local nginx server for testing TLS connections with above scanners, which makes vulnerability testing laboratory.
To run nginx you need to have `docker` installed:

```
docker run -d --name weak-tls-server \
	-p 80:80 \
	-p 443:443 \
	-v $(pwd)/nginx-tls/nginx.conf:/etc/nginx/conf.d/default.conf \
	-v $(pwd)/nginx-tls/server.crt:/etc/nginx/ssl/server.crt \
	-v $(pwd)/nginx-tls/server.key:/etc/nginx/ssl/server.key nginx
```

In this case `SupportedSuites` scanner can establish more TLS connections (including weak):
```
tls-scanner % java -cp "lib/*:out" SupportedSuites localhost
Scanning localhost on port 443 across 326 cipher suites...
This may take a moment as we test suites individually...

========================================
 Scan Results for: localhost
========================================
The server accepted the following 25 suite(s):
 - TLS_RSA_WITH_AES_128_CBC_SHA (0x2F)
 - TLS_RSA_WITH_AES_256_CBC_SHA (0x35)
 - TLS_RSA_WITH_CAMELLIA_128_CBC_SHA (0x41)
 - TLS_RSA_WITH_CAMELLIA_256_CBC_SHA (0x84)
 - TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256 (0xBA)
 - TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256 (0xC0)
 - TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (0xC013)
 - TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA (0xC014)
 - TLS_RSA_WITH_AES_128_CBC_SHA256 (0x3C)
 - TLS_RSA_WITH_AES_256_CBC_SHA256 (0x3D)
 - TLS_RSA_WITH_AES_128_GCM_SHA256 (0x9C)
 - TLS_RSA_WITH_AES_256_GCM_SHA384 (0x9D)
 - TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 (0xC027)
 - TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 (0xC028)
 - TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xC02F)
 - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (0xC030)
 - TLS_RSA_WITH_ARIA_128_GCM_SHA256 (0xC050)
 - TLS_RSA_WITH_ARIA_256_GCM_SHA384 (0xC051)
 - TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256 (0xC060)
 - TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384 (0xC061)
 - TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 (0xC076)
 - TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384 (0xC077)
 - TLS_RSA_WITH_AES_128_CCM (0xC09C)
 - TLS_RSA_WITH_AES_256_CCM (0xC09D)
 - TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (0xCCA8)
========================================
tls-scanner %
```
