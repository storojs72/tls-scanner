package tlsserver;

import org.bouncycastle.asn1.ua.UAObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.digests.DSTU7564Digest;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.tls.*;
import org.bouncycastle.tls.Certificate;
import org.bouncycastle.tls.crypto.*;
import org.bouncycastle.tls.crypto.impl.bc.*;

import common.DstuBcTlsCrypto;
import common.SharedTlsCryptoConfig;

import java.io.*;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Date;

public class BouncyCastleTlsServer {
    // Keep the parsed components in-memory at startup
    private static TlsCertificate serverTlsCert;
    private static PrivateKey serverPrivateKey;

    public static void main(String[] args) {
        if (args.length < 1) {
            System.out.println("Usage: java -cp \"lib/*:out\" BouncyCastleTlsServer <port>");
            System.out.println("Example: java -cp \"lib/*:out\" BouncyCastleTlsServer 8443");
            System.out.println("Example (if you want experimental DSTU encryption): java -cp \"lib/*:out\" BouncyCastleTlsServer 8443 dstu");
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

        System.out.println("Generating in-memory credentials using BC...");

        // Initialize BC TLS crypto using secure PRNG
        SecureRandom secureRandom = new SecureRandom();
        TlsCrypto crypto;

        if (args.length > 1 && args[1].equals("dstu")) {
            System.out.println("Using DSTU mode");
            crypto = new DstuBcTlsCrypto(secureRandom);
            generateInMemoryDstu4145Credentials(crypto);
        } else {
            crypto = new BcTlsCrypto(secureRandom);
            generateInMemoryCredentials(crypto);
        }

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
            System.err.println("[Server] TLS Handshake failed gracefully: " + e.getMessage() + " (Alert Description: " + e.getAlertDescription() + ")");
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
            return SharedTlsCryptoConfig.MY_CUSTOM_SUITES;
        }

        @Override
        public int[] getSupportedCipherSuites() {
            // Force the absolute lowest engine limits to natively allow your custom choices
            return SharedTlsCryptoConfig.MY_CUSTOM_SUITES;
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
            TlsCrypto bcCrypto = getCrypto();

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
                    if (bcCrypto instanceof BcTlsCrypto) {
                        return new BcDefaultTlsCredentialedDecryptor((BcTlsCrypto) bcCrypto, localCertChain, PrivateKeyFactory.createKey(serverPrivateKey.getEncoded()));
                    }
                    throw new RuntimeException("Unsupported crypto-provider");

                case KeyExchangeAlgorithm.ECDHE_RSA:
                case KeyExchangeAlgorithm.DHE_RSA:
                    // Required for modern ephemeral Diffie-Hellman suites (Server signs parameters)
                    System.out.println("[Server] Handshake requires an RSA Signer wrapper.");
                    if (bcCrypto instanceof BcTlsCrypto) {
                        return new BcDefaultTlsCredentialedSigner(cryptoParams, (BcTlsCrypto) bcCrypto, PrivateKeyFactory.createKey(serverPrivateKey.getEncoded()), localCertChain, selectedAlg);
                    }
                    throw new RuntimeException("Unsupported crypto-provider");

                case KeyExchangeAlgorithm.NULL:
                    // TLS 1.3 completely eliminates explicit KeyExchangeAlgorithm constants in BC
                    // It relies on internal HKDF mechanisms, but still requires a Signer for the CertificateVerify packet
                    if (TlsUtils.isTLSv13(context)) {
                        System.out.println("[Server] TLS 1.3 Handshake requires an RSA Signer wrapper.");
                        if (bcCrypto instanceof DstuBcTlsCrypto) {
                            System.out.println("[Server] Using DSTU-4145 signing of the CertificateVerify packet");
                            return new BcDstuDefaultTlsCredentialedSigner(cryptoParams, serverPrivateKey, localCertChain, selectedAlg);
                        }

                        if (bcCrypto instanceof BcTlsCrypto) {
                            return new BcDefaultTlsCredentialedSigner(cryptoParams, (BcTlsCrypto) bcCrypto, PrivateKeyFactory.createKey(serverPrivateKey.getEncoded()), localCertChain, selectedAlg);
                        }
                        throw new RuntimeException("Unsupported crypto-provider");
                    }

                default:
                    throw new TlsFatalAlert(AlertDescription.internal_error, new IllegalStateException("Unsupported key exchange algorithm: " + keyExchangeAlgorithm));
            }
        }
    }

    public static class BcDstuDefaultTlsCredentialedSigner extends DefaultTlsCredentialedSigner {
        public BcDstuDefaultTlsCredentialedSigner(TlsCryptoParameters cryptoParams, PrivateKey privateKey, Certificate certificate, SignatureAndHashAlgorithm signatureAndHashAlgorithm) {
            super(cryptoParams, new BcTlsDstu4145Signer(privateKey), certificate, signatureAndHashAlgorithm);
        }
    }

    public static class BcTlsDstu4145Signer implements TlsSigner {
        PrivateKey privateKey;

        public BcTlsDstu4145Signer(PrivateKey privateKey) {
            this.privateKey = privateKey;
        }

        public byte[] generateRawSignature(SignatureAndHashAlgorithm algorithm, byte[] hash) {
            byte[] signature = null;
            try {
                Signature signer = Signature.getInstance("DSTU4145", new BouncyCastleProvider());
                signer.initSign(privateKey);
                signer.update(hash);
                signature = signer.sign();
            } catch (Exception e) {
                e.printStackTrace();
            }
            return signature;
        }

        @Override
        public TlsStreamSigner getStreamSigner(SignatureAndHashAlgorithm signatureAndHashAlgorithm) throws IOException {
            return null;
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

            X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(dnName, certSerialNumber, startDate, endDate, dnName, keyPair.getPublic());

            ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate());
            X509Certificate certificate = new JcaX509CertificateConverter().getCertificate(certBuilder.build(contentSigner));

            // just to ensure that certificate is verifiable
            certificate.verify(certificate.getPublicKey());

            byte[] encodedCertBytes = certificate.getEncoded();
            serverTlsCert = crypto.createCertificate(encodedCertBytes);
            serverPrivateKey = keyPair.getPrivate();

            System.out.println("Server's in-memory certificate has been generated");
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate structural BC credentials", e);
        }
    }

    // In-memory DSTU certificate generator
    public static void generateInMemoryDstu4145Credentials(TlsCrypto crypto) {
        try {
            // 1. Generate DSTU 4145 Key Pair
            ECDomainParameters dstuParams = SharedTlsCryptoConfig.DSTU4145_CURVE_ID;

            ECParameterSpec spec = new ECParameterSpec(
                    dstuParams.getCurve(),
                    dstuParams.getG(),
                    dstuParams.getN(),
                    dstuParams.getH()
            );

            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSTU4145", new BouncyCastleProvider());
            keyGen.initialize(spec, new SecureRandom());
            KeyPair keyPair = keyGen.generateKeyPair();


            // 2. Set Up Certificate Metadata
            X500Name dnName = new X500Name("CN=BouncyCastleTestServer, O=DevEnvironment, C=US");
            BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());
            Date notBefore = new Date(System.currentTimeMillis() - 86400000L); // Yesterday
            Date notAfter = new Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000); // 1 Year

            // 3. Build the Certificate Structure
            SubjectPublicKeyInfo pubKeyInfo = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());

            System.out.println("Public key size: " + pubKeyInfo.getEncoded().length);

            X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                    dnName,
                    serialNumber,
                    notBefore,
                    notAfter,
                    dnName,
                    pubKeyInfo
            );

            Dstu4145ContentSigner contentSigner = new Dstu4145ContentSigner(keyPair.getPrivate());

            X509CertificateHolder certificateHolder = certBuilder.build(contentSigner);
            X509Certificate certificate = new JcaX509CertificateConverter()
                    .setProvider(new BouncyCastleProvider())
                    .getCertificate(certificateHolder);

            serverTlsCert = crypto.createCertificate(certificate.getEncoded());

            // 4. Just to ensure that certificate is verifiable
            PublicKey publicKey = keyPair.getPublic();

            Signature signer = Signature.getInstance("DSTU4145", new BouncyCastleProvider());
            signer.initVerify(publicKey);

            byte[] data = certificate.getTBSCertificate();
            byte[] hash = new byte[32];
            DSTU7564Digest digest = new DSTU7564Digest(256);
            digest.update(data, 0, data.length);
            digest.doFinal(hash, 0);

            signer.update(hash);

            boolean verified = signer.verify(certificate.getSignature());
            System.out.println("Certificate generated and verified. Result:" + verified);

            serverPrivateKey = keyPair.getPrivate();

            System.out.println("DSTU-specific server's in-memory certificate has been generated");
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate DSTU4145 credentials", e);
        }
    }

    public static class Dstu4145ContentSigner implements ContentSigner {
        private final ByteArrayOutputStream stream;
        private final Signature signer;

        public Dstu4145ContentSigner(PrivateKey privateKey) throws Exception {
            signer = Signature.getInstance("DSTU4145", new BouncyCastleProvider());
            signer.initSign(privateKey);
            stream = new ByteArrayOutputStream();
        }

        @Override
        public AlgorithmIdentifier getAlgorithmIdentifier() {
            return new AlgorithmIdentifier(UAObjectIdentifiers.dstu4145le);
        }

        @Override
        public OutputStream getOutputStream() {
            return stream;
        }

        @Override
        public byte[] getSignature() {
            byte[] signature = null;
            try {
                byte[] dataToSign = stream.toByteArray();
                byte[] hash = new byte[32];
                DSTU7564Digest digest = new DSTU7564Digest(256);
                digest.update(dataToSign, 0, dataToSign.length);
                digest.doFinal(hash, 0);

                signer.update(hash);

                signature = signer.sign();
            } catch (Exception e) {
                e.printStackTrace();
            }
            return signature;
        }
    }
}
