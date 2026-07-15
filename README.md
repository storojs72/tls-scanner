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
