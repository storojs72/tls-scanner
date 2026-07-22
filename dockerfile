FROM eclipse-temurin:17-jdk AS build
WORKDIR /app

ENV SERVER_PORT=8443

# Copy your local precompiled JAR files into the build environment
COPY lib/bcprov*.jar bcprov.jar
COPY lib/bctls*.jar bctls.jar
COPY lib/bcutil*.jar bcutil.jar
COPY lib/bcpkix*.jar bcpkix.jar
COPY BouncyCastleTlsServer.java .
COPY SharedTlsConfig.java .

# Compile using your local Bouncy Castle files
RUN javac -cp "bcprov.jar:bctls.jar:bcutil.jar:bcpkix.jar" SharedTlsConfig.java BouncyCastleTlsServer.java

EXPOSE ${SERVER_PORT}

CMD java -cp .:bcprov.jar:bctls.jar:bcutil.jar:bcpkix.jar BouncyCastleTlsServer $SERVER_PORT
