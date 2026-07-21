FROM eclipse-temurin:17-jdk AS build
WORKDIR /app

# Define configuration defaults (can be overridden during build)
ENV KEYSTORE_PASSWORD=password
ENV SERVER_PORT=8443

# Copy your local precompiled JAR files into the build environment
COPY lib/bcprov*.jar bcprov.jar
COPY lib/bctls*.jar bctls.jar
COPY lib/bcutil*.jar bcutil.jar
COPY BouncyCastleTlsServer.java .

RUN keytool -genkeypair \
    -alias bctls \
    -keyalg RSASSA-PSS \
    -keysize 2048 \
    -storetype PKCS12 \
    -keystore server.p12 \
    -validity 365 \
    -dname "CN=localhost" \
    -storepass "${KEYSTORE_PASSWORD}"

# Compile using your local Bouncy Castle files
RUN javac -cp "bcprov.jar:bctls.jar:bcutil.jar" BouncyCastleTlsServer.java

EXPOSE ${SERVER_PORT}

CMD java -cp .:bcprov.jar:bctls.jar:bcutil.jar BouncyCastleTlsServer server.p12 $KEYSTORE_PASSWORD $SERVER_PORT
