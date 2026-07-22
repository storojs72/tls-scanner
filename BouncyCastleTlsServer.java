import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.tls.*;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.impl.bc.BcDefaultTlsCredentialedDecryptor;
import org.bouncycastle.tls.crypto.impl.bc.BcDefaultTlsCredentialedSigner;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;

import java.io.*;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Date;

public class BouncyCastleTlsServer {
    // Keep the parsed components in-memory at startup
    private static TlsCertificate serverTlsCert;
    private static AsymmetricKeyParameter serverPrivateKey;

    public static void main(String[] args) {
        if (args.length < 1) {
            System.out.println("Usage: java -cp \"lib/*:out\" BouncyCastleTlsServer <port>");
            System.out.println("Example: java -cp \"lib/*:out\" BouncyCastleTlsServer 8443");
            return;
        }
        int port = 0;
        try {
            port = Integer.parseInt(args[0]);
        } catch (Exception e) {
            System.out.println("Specified port is invalid");
            e.printStackTrace();
            System.exit(1);
        }

        // Initialize BC TLS crypto using secure PRNG
        SecureRandom secureRandom = new SecureRandom();
        TlsCrypto crypto = new BcTlsCrypto(secureRandom);

        System.out.println("Generating in-memory credentials using BC...");
        generateInMemoryCredentials(crypto);
        System.out.println("Starting server...");
        try (ServerSocket serverSocket = new ServerSocket(port)) {
            while (true) {
                try {
                    Socket clientSocket = serverSocket.accept();
                    System.out.println("[Server] Raw TCP connection accepted from: " + clientSocket.getRemoteSocketAddress());

                    // Hand off the raw socket connection to a separate thread
                    new Thread(() -> handleClient(clientSocket, crypto)).start();
                } catch (IOException e) {
                    System.out.println("[Server] Error accepting client connection: " + e.getMessage());
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void handleClient(Socket socket, TlsCrypto crypto) {
        TlsServerProtocol tlsServerProtocol = null;

        try {
            // Extract raw TCP streams
            InputStream rawIn = socket.getInputStream();
            OutputStream rawOut = socket.getOutputStream();

            // Initialize BC's low-level protocol handler to overlay raw TCP streams
            tlsServerProtocol = new TlsServerProtocol(rawIn, rawOut);

            // Bind our custom TLS configuration and state machine logic
            TlsServer server = new CustomBcTlsServer(crypto);

            System.out.println("[Server] Initiating Bouncy Castle TLS handshake...");

            // Explicitely execute TLS handshake
            tlsServerProtocol.accept(server);
            System.out.println("[Server] Handshake completed successfully.");

            // Get secure application-level streams managed by BouncyCastle
            InputStream tlsIn = tlsServerProtocol.getInputStream();
            OutputStream tlsOut = tlsServerProtocol.getOutputStream();

            // Read secure payload sent by client
            BufferedReader reader = new BufferedReader(new InputStreamReader(tlsIn));
            String clientMessage = reader.readLine();
            if (clientMessage != null) {
                System.out.println("[Server] Received message: \"" + clientMessage + "\"");
                String response = "Hello from the pure Bouncy Castle TLS Server!\n";
                tlsOut.write(response.getBytes());
                tlsOut.flush();
            }
        } catch (TlsFatalAlert e) {
            // Catch specific TLS failures (like handshake_failure(40)) cleanly
            System.err.println("[Server] TLS Handshake failed gracefully: " + e.getMessage()
                    + " (Alert Description: " + e.getAlertDescription() + ")");
            e.printStackTrace();
        } catch (IOException e) {
            System.err.println("[Server] Network I/O breakdown: " + e.getMessage());
        } finally {
            // Ensure system network resources are freed under ALL circumstances
            if (tlsServerProtocol != null) {
                try {
                    tlsServerProtocol.close();
                } catch (Exception ignored) {
                }
            }
            try {
                socket.close();
            } catch (Exception ignored) {
            }
            System.out.println("[Server] Worker thread execution finished. Socket released.");
        }
    }

    /*
     *   Implements Bouncy Castle's engine hooks to serve handshake requirements
     */
    private static class CustomBcTlsServer extends DefaultTlsServer {
        public CustomBcTlsServer(TlsCrypto crypto) {
            super(crypto);
        }

        @Override
        public int[] getCipherSuites() {
            // Exclusively allow the suites defined in our shared configuration
            return SharedTlsConfig.MY_CUSTOM_SUITES;
        }

        @Override
        public int[] getSupportedCipherSuites() {
            // Force the absolute lowest engine limits to natively allow your custom choices
            return SharedTlsConfig.MY_CUSTOM_SUITES;
        }

        @Override
        protected ProtocolVersion[] getSupportedVersions() {
            return ProtocolVersion.TLSv13.downTo(ProtocolVersion.TLSv12);
        }

        @Override
        public TlsCredentials getCredentials() throws IOException {
            /*
             * Lazily construct BcDefaultTlsCredentialedSigner using the parameters object.
             */
            TlsCryptoParameters cryptoParams = new TlsCryptoParameters(this.context);
            BcTlsCrypto bcCrypto = (BcTlsCrypto) getCrypto();

            int keyExchangeAlgorithm = context.getSecurityParametersHandshake().getKeyExchangeAlgorithm();

            SignatureAndHashAlgorithm selectedAlg = null;

            if (TlsUtils.isSignatureAlgorithmsExtensionAllowed(context.getServerVersion())) {
                java.util.Vector clientSigAlgs = context.getSecurityParametersHandshake().getClientSigAlgs();

                if (clientSigAlgs != null && !clientSigAlgs.isEmpty()) {
                    selectedAlg = TlsUtils.chooseSignatureAndHashAlgorithm(context, clientSigAlgs, SignatureAlgorithm.rsa);
                }
            }

            // Fallback for legacy clients if negotiation was skipped
            if (selectedAlg == null) {
                selectedAlg = new SignatureAndHashAlgorithm(HashAlgorithm.sha256, SignatureAlgorithm.rsa);
            }

            // ==================== DYNAMIC VERSION-BASED CERTIFICATE CREATION ====================
            Certificate localCertChain;

            if (TlsUtils.isTLSv13(context)) {
                // TLS 1.3: Requires the CertificateEntry structure WITH an explicit extensions map
                // AND a non-null (empty) request context array.
                System.out.println("[Server] Building TLS 1.3 compliant Certificate layout...");
                java.util.Hashtable extensions = new java.util.Hashtable();
                CertificateEntry certEntry = new CertificateEntry(serverTlsCert, extensions);
                CertificateEntry[] certificateEntryList = new CertificateEntry[]{certEntry};
                byte[] certificateRequestContext = new byte[0]; // Strict requirement for TLS 1.3

                localCertChain = new Certificate(certificateRequestContext, certificateEntryList);
            } else {
                // TLS 1.2: Requires the legacy array structure to avoid IllegalStateException.
                System.out.println("[Server] Building TLS 1.2 compliant Certificate layout...");
                TlsCertificate[] certArray = new TlsCertificate[]{serverTlsCert};

                localCertChain = new Certificate(certArray);
            }
            // ====================================================================================


            switch (keyExchangeAlgorithm) {
                case KeyExchangeAlgorithm.RSA:
                    // Required for legacy plain "TLS_RSA_WITH_..." suites (Server decrypts pre-master secret)
                    System.out.println("[Server] Handshake requires an RSA Decryptor wrapper.");
                    return new BcDefaultTlsCredentialedDecryptor(bcCrypto, localCertChain, serverPrivateKey);

                case KeyExchangeAlgorithm.ECDHE_RSA:
                case KeyExchangeAlgorithm.DHE_RSA:
                    // Required for modern ephemeral Diffie-Hellman suites (Server signs parameters)
                    System.out.println("[Server] Handshake requires an RSA Signer wrapper.");
                    return new BcDefaultTlsCredentialedSigner(cryptoParams, bcCrypto, serverPrivateKey, localCertChain, selectedAlg);

                case KeyExchangeAlgorithm.NULL:
                    // TLS 1.3 completely eliminates explicit KeyExchangeAlgorithm constants in BC
                    // It relies on internal HKDF mechanisms, but still requires a Signer for the CertificateVerify packet
                    if (TlsUtils.isTLSv13(context)) {
                        System.out.println("[Server] TLS 1.3 Handshake requires an RSA Signer wrapper.");
                        return new BcDefaultTlsCredentialedSigner(cryptoParams, bcCrypto, serverPrivateKey, localCertChain, selectedAlg);
                    }

                default:
                    throw new TlsFatalAlert(AlertDescription.internal_error,
                            new IllegalStateException("Unsupported key exchange algorithm: " + keyExchangeAlgorithm));
            }
        }
    }

    /*
     *   Helper utility generating localized memory-backed credentials
     */
    private static void generateInMemoryCredentials(TlsCrypto crypto) {
        try {
            // Generate KeyPair using standard Java (for simplicity)
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            KeyPair keyPair = keyGen.generateKeyPair();

            // Construct X.509 Test Certificate structure purely inside Bouncy Castle
            X500Name dnName = new X500Name("CN=BouncyCastleTestServer, O=DevEnvironment, C=US");
            BigInteger certSerialNumber = BigInteger.valueOf(System.currentTimeMillis());
            Date startDate = new Date(System.currentTimeMillis() - 86400000L); // Yesterday
            Date endDate = new Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000); // 1 Year

            X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                    dnName, certSerialNumber, startDate, endDate, dnName, keyPair.getPublic());

            ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate());
            X509Certificate certificate = new JcaX509CertificateConverter().getCertificate(certBuilder.build(contentSigner));

            byte[] encodedCertBytes = certificate.getEncoded();
            serverTlsCert = crypto.createCertificate(encodedCertBytes);
            serverPrivateKey = org.bouncycastle.crypto.util.PrivateKeyFactory.createKey(keyPair.getPrivate().getEncoded());

        } catch (Exception e) {
            throw new RuntimeException("Failed to generate structural BC credentials", e);
        }
    }
}
