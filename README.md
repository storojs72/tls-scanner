# TLS scanner

Basic scanner of TLS connections via BouncyCastle crypto-provider.

Tested only on MacOS currently.

The project contains source code of `bctls` library (v2.73.11) which is compiled under-the-hood and used as a dependency for applications located in `executables/`:

- `common` library is a wrapper for `bctls` dependency
- `tlstest` cmd-line application for simple testing that TLS connection can be established with the host using default 0x1303 cipher suite (TLS_CHACHA20_POLY1305_SHA256)
- `scanner` cmd-line application for establishing multiple TLS handshakes one-by-one by iterating cipher suites from `SharedTlsCryptoConfig.java`
- `tlsserver` cmd-line application - server based on `bctls` used for debugging `scanner` application

## Prerequisites

Project uses Gradle build system, so You need to have Gradle (v9.7.1) and OpenJDK (v26.0.2.1) as prerequisites.
If not installed, try installing them via homebrew:

```
brew install openjdk
brew install gradle
```

## Build and Run

```
tls-scanner % ./gradlew :executables:tlstest:run --args "github.com 443"

> Task :executables:tlstest:run
Connecting to github.com on port 443...
Handshake successful! Server certificate received.

========================================
Negotiated Cipher Suite: (0x1303)
========================================

cert[0] signature algorithm: SHA256WITHECDSA
cert[1] signature algorithm: SHA384WITHECDSA
cert[2] signature algorithm: SHA384WITHECDSA

========================================

BUILD SUCCESSFUL in 1s
5 actionable tasks: 1 executed, 4 up-to-date
Consider enabling configuration cache to speed up this build: https://docs.gradle.org/9.7.1/userguide/configuration_cache_enabling.html
tls-scanner % 
```

```
tls-scanner % ./gradlew :executables:scanner:run --args "github.com 443"

> Task :executables:scanner:run
Scanning github.com on port 443 across 3 cipher suites...
This may take a moment as we test suites individually...

[Client-Auth] Server's certificate validation is OK
Connected!!!
--- Decrypted Payload Response from Server ---
HTTP/1.1 200 OK
[Client-Auth] Server's certificate validation is OK
Connected!!!
--- Decrypted Payload Response from Server ---
HTTP/1.1 200 OK
[Client-Auth] Server's certificate validation is OK
Connected!!!
--- Decrypted Payload Response from Server ---
HTTP/1.1 200 OK
========================================
 Scan Results for: github.com
========================================
The server accepted the following 3 suite(s):
 - TLS_AES_256_GCM_SHA384 (0x1302)
 - TLS_AES_128_GCM_SHA256 (0x1301)
 - TLS_CHACHA20_POLY1305_SHA256 (0x1303)
========================================

BUILD SUCCESSFUL in 2s
7 actionable tasks: 4 executed, 3 up-to-date
Consider enabling configuration cache to speed up this build: https://docs.gradle.org/9.7.1/userguide/configuration_cache_enabling.html
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

In this case `scanner` can establish more TLS connections:
```
tls-scanner % ./gradlew :executables:scanner:run --args "localhost 443"

> Task :executables:scanner:run
Scanning localhost on port 443 across 25 cipher suites...
This may take a moment as we test suites individually...

[Client-Auth] Server's certificate validation is OK
Connected!!!
--- Decrypted Payload Response from Server ---
HTTP/1.1 200 OK
[Client-Auth] Server's certificate validation is OK
Connected!!!
--- Decrypted Payload Response from Server ---
HTTP/1.1 200 OK
[Client-Auth] Server's certificate validation is OK
Connected!!!

. . .

[Client-Auth] Server's certificate validation is OK
Connected!!!
--- Decrypted Payload Response from Server ---
HTTP/1.1 200 OK
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

BUILD SUCCESSFUL in 863ms
7 actionable tasks: 3 executed, 4 up-to-date
Consider enabling configuration cache to speed up this build: https://docs.gradle.org/9.7.1/userguide/configuration_cache_enabling.html
artemstorozhuk@Artems-MacBook-Pro tls-scanner %
```

For `scanner` development purposes there is a BouncyCastle-based TLS server that could be useful for debugging handshakes with custom cipher suites:

Logs from `tlsserver`:
```
tls-scanner % ./gradlew :executables:tlsserver:run --args "8443"

> Task :executables:tlsserver:run
Generating in-memory credentials using BC...
Server's in-memory certificate has been generated
Starting server...
[Server] Raw TCP connection accepted from: /127.0.0.1:59931
[Server] Initiating Bouncy Castle TLS handshake...
[Server] Building TLS 1.3 compliant Certificate layout...
[Server] TLS 1.3 Handshake requires an RSA Signer wrapper.
[Server] Handshake completed successfully.
[Server] Received message: "GET / HTTP/1.1"
[Server] Worker thread execution finished. Socket released.
[Server] Raw TCP connection accepted from: /127.0.0.1:59932
[Server] Initiating Bouncy Castle TLS handshake...
[Server] Building TLS 1.3 compliant Certificate layout...
[Server] TLS 1.3 Handshake requires an RSA Signer wrapper.
[Server] Handshake completed successfully.
[Server] Received message: "GET / HTTP/1.1"
[Server] Worker thread execution finished. Socket released.
[Server] Raw TCP connection accepted from: /127.0.0.1:59933
[Server] Initiating Bouncy Castle TLS handshake...
[Server] Building TLS 1.3 compliant Certificate layout...
[Server] TLS 1.3 Handshake requires an RSA Signer wrapper.
[Server] Handshake completed successfully.
[Server] Received message: "GET / HTTP/1.1"
[Server] Worker thread execution finished. Socket released.
[Server] Raw TCP connection accepted from: /127.0.0.1:59934
[Server] Initiating Bouncy Castle TLS handshake...
[Server] Building TLS 1.2 compliant Certificate layout...
[Server] Handshake requires an RSA Signer wrapper.
[Server] Handshake completed successfully.
[Server] Received message: "GET / HTTP/1.1"
[Server] Worker thread execution finished. Socket released.
[Server] Raw TCP connection accepted from: /127.0.0.1:59935
[Server] Initiating Bouncy Castle TLS handshake...
[Server] Building TLS 1.2 compliant Certificate layout...
[Server] Handshake requires an RSA Signer wrapper.
[Server] Handshake completed successfully.
[Server] Received message: "GET / HTTP/1.1"
[Server] Worker thread execution finished. Socket released.
[Server] Raw TCP connection accepted from: /127.0.0.1:59936
[Server] Initiating Bouncy Castle TLS handshake...
[Server] Building TLS 1.2 compliant Certificate layout...
[Server] Handshake requires an RSA Signer wrapper.
[Server] Handshake completed successfully.
[Server] Received message: "GET / HTTP/1.1"
[Server] Worker thread execution finished. Socket released.
[Server] Raw TCP connection accepted from: /127.0.0.1:59937
[Server] Initiating Bouncy Castle TLS handshake...
[Server] Building TLS 1.2 compliant Certificate layout...
[Server] Handshake requires an RSA Signer wrapper.
[Server] Handshake completed successfully.
[Server] Received message: "GET / HTTP/1.1"
[Server] Worker thread execution finished. Socket released.
[Server] Raw TCP connection accepted from: /127.0.0.1:59938
[Server] Initiating Bouncy Castle TLS handshake...
[Server] Building TLS 1.2 compliant Certificate layout...
[Server] Handshake requires an RSA Decryptor wrapper.
[Server] Handshake completed successfully.
[Server] Received message: "GET / HTTP/1.1"
[Server] Worker thread execution finished. Socket released.
[Server] Raw TCP connection accepted from: /127.0.0.1:59939
[Server] Initiating Bouncy Castle TLS handshake...
[Server] Building TLS 1.2 compliant Certificate layout...
[Server] Handshake requires an RSA Decryptor wrapper.
[Server] Handshake completed successfully.
[Server] Received message: "GET / HTTP/1.1"
[Server] Worker thread execution finished. Socket released.
│█████████████▊·│ 92% EXECUTING [34s]
> :executables:tlsserver:run
```

Logs from `scanner`:
```
tls-scanner % ./gradlew :executables:scanner:run --args "localhost 8443"
Starting a Gradle Daemon, 1 busy Daemon could not be reused, use --status for details

> Task :executables:scanner:run
Scanning localhost on port 8443 across 9 cipher suites...
This may take a moment as we test suites individually...

[Client-Auth] Server's certificate validation is OK
Connected!!!
--- Decrypted Payload Response from Server ---
Hello from the pure Bouncy Castle TLS Server!
[Client-Auth] Server's certificate validation is OK
Connected!!!
--- Decrypted Payload Response from Server ---
Hello from the pure Bouncy Castle TLS Server!

. . .

[Client-Auth] Server's certificate validation is OK
Connected!!!
--- Decrypted Payload Response from Server ---
Hello from the pure Bouncy Castle TLS Server!
========================================
 Scan Results for: localhost
========================================
The server accepted the following 9 suite(s):
 - TLS_AES_256_GCM_SHA384 (0x1302)
 - TLS_AES_128_GCM_SHA256 (0x1301)
 - TLS_CHACHA20_POLY1305_SHA256 (0x1303)
 - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (0xC030)
 - TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xC02F)
 - TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 (0x9F)
 - TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 (0x9E)
 - TLS_RSA_WITH_AES_256_GCM_SHA384 (0x9D)
 - TLS_RSA_WITH_AES_128_GCM_SHA256 (0x9C)
========================================

BUILD SUCCESSFUL in 3s
7 actionable tasks: 1 executed, 6 up-to-date
Consider enabling configuration cache to speed up this build: https://docs.gradle.org/9.7.1/userguide/configuration_cache_enabling.html
tls-scanner % 
```

It is also possible to enable experimental DSTU algorithms substitution inside established TLS session. The whole TLS machinery is kept unchanged, meaning that client/server "think" that they use default cipher-suite (e.g. TLS_AES_256_GCM_SHA384), but internally in this mode the default TLS cryptography specified in cipher-suite is replaced by DSTU algorithms:
 - AES-GCM -> DSTU7624-GCM,
 - SHA -> DSTU7564,
 - Diffie-Hellman with X25519 -> Diffie-Hellman with DSTU curve,
 - RSAwithSha256 signed certificate -> DSTU4145 signed certificate

Concrete DSTU curve used for signature and Diffie-Hellman algorithm can also be configured.

Important note: The CertificateVerify packet validation with DSTU4145 signing/verifying is not currently
supported as it requires modifying some internals of `bctls` library, so currently it is stubbed. Also,
TLS 1.2 is not currently supported in DSTU-mode (and stubbing it - not possible in current setup)
for the same reasons.

In this case server needs to be specifically compiled and launched with `dstu` flag:

Logs on `tlsserver` in dstu-mode:
```
tls-scanner % ./gradlew :executables:tlsserver:run --args "8443 dstu"

> Task :executables:tlsserver:run
Generating in-memory credentials using BC...
Using DSTU mode
Public key size: 276
Certificate generated and verified. Result:true
DSTU-specific server's in-memory certificate has been generated
Starting server...
[Server] Raw TCP connection accepted from: /127.0.0.1:59950
[Server] Initiating Bouncy Castle TLS handshake...
[Server] Building TLS 1.3 compliant Certificate layout...
[Server] TLS 1.3 Handshake requires an RSA Signer wrapper.
[Server] Using DSTU-4145 signing of the CertificateVerify packet
[Server] Handshake completed successfully.
[Server] Received message: "GET / HTTP/1.1"
[Server] Worker thread execution finished. Socket released.
[Server] Raw TCP connection accepted from: /127.0.0.1:59951
[Server] Initiating Bouncy Castle TLS handshake...
[Server] Building TLS 1.3 compliant Certificate layout...
[Server] TLS 1.3 Handshake requires an RSA Signer wrapper.
[Server] Using DSTU-4145 signing of the CertificateVerify packet
[Server] Handshake completed successfully.
[Server] Received message: "GET / HTTP/1.1"
[Server] Worker thread execution finished. Socket released.
[Server] Raw TCP connection accepted from: /127.0.0.1:59952
[Server] Initiating Bouncy Castle TLS handshake...
[Server] Building TLS 1.3 compliant Certificate layout...
[Server] TLS 1.3 Handshake requires an RSA Signer wrapper.
[Server] Using DSTU-4145 signing of the CertificateVerify packet
[Server] Handshake completed successfully.
[Server] Received message: "GET / HTTP/1.1"
[Server] Worker thread execution finished. Socket released.
│█████████████▊·│ 92% EXECUTING [59s]
tls-scanner %
```

Logs on `scanner` in dstu-mode:
```
tls-scanner % ./gradlew :executables:scanner:run --args "localhost 8443 dstu"

> Task :executables:scanner:run
Scanning localhost on port 8443 across 3 cipher suites...
This may take a moment as we test suites individually...

Using DSTU mode
DSTU-specific certificate validation: extract public key and signature and verify the signature
Public key size: 276
[Client-Auth] Server's certificate validation (in DSTU mode) is OK
Calling verifySignature in DSTU mode (TLS 1.3)
Connected!!!
--- Decrypted Payload Response from Server ---
Hello from the pure Bouncy Castle TLS Server!
DSTU-specific certificate validation: extract public key and signature and verify the signature
Public key size: 276
[Client-Auth] Server's certificate validation (in DSTU mode) is OK
Calling verifySignature in DSTU mode (TLS 1.3)
Connected!!!
--- Decrypted Payload Response from Server ---
Hello from the pure Bouncy Castle TLS Server!
DSTU-specific certificate validation: extract public key and signature and verify the signature
Public key size: 276
[Client-Auth] Server's certificate validation (in DSTU mode) is OK
Calling verifySignature in DSTU mode (TLS 1.3)
Connected!!!
--- Decrypted Payload Response from Server ---
Hello from the pure Bouncy Castle TLS Server!
========================================
 Scan Results for: localhost
========================================
The server accepted the following 3 suite(s):
 - TLS_AES_256_GCM_SHA384 (0x1302)
 - TLS_AES_128_GCM_SHA256 (0x1301)
 - TLS_CHACHA20_POLY1305_SHA256 (0x1303)
========================================

BUILD SUCCESSFUL in 969ms
7 actionable tasks: 1 executed, 6 up-to-date
Consider enabling configuration cache to speed up this build: https://docs.gradle.org/9.7.1/userguide/configuration_cache_enabling.html
tls-scanner %
```
