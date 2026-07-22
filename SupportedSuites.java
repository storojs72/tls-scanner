import org.bouncycastle.tls.*;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;

import java.io.IOException;
import java.lang.reflect.Field;
import java.net.Socket;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class SupportedSuites {

    public static void main(String[] args) {
        if (args.length < 1) {
            System.out.println("Usage: java -cp \"lib/*:out\" SupportedSuites <hostname>");
            return;
        }

        // Grab host and port from command line
        String host = args[0];
        int port = 0;
        try {
            port = Integer.parseInt(args[1]);
        } catch (Exception e) {
            System.out.println("Specified port is invalid");
            e.printStackTrace();
            System.exit(1);
        }

        // 1. Gather cipher suites that we want to test
        //List<Integer> allSuites = getAllKnownCipherSuites();
        List<Integer> allSuites = Arrays.stream(SharedTlsConfig.MY_CUSTOM_SUITES).boxed().toList();
        ;
        List<String> supportedSuites = new ArrayList<>();

        System.out.println("Scanning " + host + " on port " + port + " across " + allSuites.size() + " cipher suites...");
        System.out.println("This may take a moment as we test suites individually...\n");

        BcTlsCrypto crypto = new BcTlsCrypto(new SecureRandom());

        // 2. Multi-pass loop: Test each cipher suite one by one
        for (int suiteCode : allSuites) {
            String suiteName = getCipherSuiteName(suiteCode);

            try (Socket socket = new Socket(host, port)) {
                // Set a brief timeout so dead suites don't hang the scanner
                socket.setSoTimeout(3000);

                TlsClientProtocol tlsClientProtocol = new TlsClientProtocol(
                        socket.getInputStream(),
                        socket.getOutputStream()
                );

                // Override the client to ONLY offer this single cipher suite
                tlsClientProtocol.connect(new ConfigurableTlsClient(crypto, suiteCode) {
                    @Override
                    public int[] getCipherSuites() {
                        return new int[]{suiteCode};
                    }

                    @Override
                    public TlsAuthentication getAuthentication() {
                        return new ServerOnlyTlsAuthentication() {
                            @Override
                            public void notifyServerCertificate(TlsServerCertificate serverCertificate) {
                                // Handshake reached certificate phase successfully
                            }
                        };
                    }
                });

                // If no exception was thrown, the handshake succeeded!
                supportedSuites.add(suiteName + " (0x" + Integer.toHexString(suiteCode).toUpperCase() + ")");
                tlsClientProtocol.close();

            } catch (IOException e) {
                // Handshake failed or was rejected by the server for this suite.
                // We silently ignore this and move to the next suite.
            } catch (Exception e) {
                // Ignore general evaluation snags
            }
        }

        // 3. Print the final results
        System.out.println("========================================");
        System.out.println(" Scan Results for: " + host);
        System.out.println("========================================");
        if (supportedSuites.isEmpty()) {
            System.out.println("No matching cipher suites found (or server rejected the scan).");
        } else {
            System.out.println("The server accepted the following " + supportedSuites.size() + " suite(s):");
            for (String suite : supportedSuites) {
                System.out.println(" - " + suite);
            }
        }
        System.out.println("========================================");
    }

    public static class ConfigurableTlsClient extends DefaultTlsClient {

        private final int targetCipherSuite;

        public ConfigurableTlsClient(TlsCrypto crypto, int targetCipherSuite) {
            super(crypto);
            this.targetCipherSuite = targetCipherSuite;
        }

        @Override
        protected int[] getSupportedCipherSuites() {
            // Enforce the client to offer ONLY this specific suite for this connection test
            return new int[]{targetCipherSuite};
        }

        @Override
        public int[] getCipherSuites() {
            return new int[]{targetCipherSuite};
        }

        @Override
        public ProtocolVersion[] getProtocolVersions() {
            // Dynamic downgrade rule: If it's a legacy TLS 1.2 suite, block the client from offering TLS 1.3
            if (isTls13Suite(targetCipherSuite)) {
                return new ProtocolVersion[]{ProtocolVersion.TLSv13};
            } else {
                // For TLS 1.2 suites (like ECDHE_RSA), strictly limit the negotiation window to TLS 1.2
                return new ProtocolVersion[]{ProtocolVersion.TLSv12};
            }
        }

        /**
         * Helper check to segregate modern TLS 1.3 suites from legacy TLS 1.2 suites
         */
        private boolean isTls13Suite(int cipherSuite) {
            return cipherSuite == CipherSuite.TLS_AES_256_GCM_SHA384 ||
                    cipherSuite == CipherSuite.TLS_AES_128_GCM_SHA256 ||
                    cipherSuite == CipherSuite.TLS_CHACHA20_POLY1305_SHA256;
        }

        @Override
        public TlsAuthentication getAuthentication() throws IOException {
            /*
             * This handles verifying the server's identity.
             * For testing multi-cipher suites with our self-signed server cert,
             * we return an authentication structure that blindly accepts the server's credentials.
             */
            return new ServerOnlyTlsAuthentication();
        }

        /**
         * A permissive validation handler to skip rigid trust manager chain checks for test loops.
         */
        public static class ServerOnlyTlsAuthentication implements TlsAuthentication {
            @Override
            public void notifyServerCertificate(TlsServerCertificate tlsServerCertificate) throws IOException {
                // For testing loops, log that we saw the cert chain and proceed
                System.out.println("[Client-Auth] Inspected server certificate chain. Length: "
                        + tlsServerCertificate.getCertificate().getLength());
            }

            @Override
            public TlsCredentials getClientCredentials(CertificateRequest certificateRequest) throws IOException {
                return null;
            }
        }
    }

    /**
     * Uses reflection to pull all raw integer cipher suites from Bouncy Castle.
     */
//    private static List<Integer> getAllKnownCipherSuites() {
//        List<Integer> suites = new ArrayList<>();
//        for (Field field : CipherSuite.class.getFields()) {
//            try {
//                if (field.getType() == int.class) {
//                    int value = field.getInt(null);
//                    // Filter out signaling/scsv placeholders that aren't real ciphers
//                    if (field.getName().contains("SCSV") || field.getName().equals("EMPTY_RENEGOTIATION_INFO_SCSV")) {
//                        continue;
//                    }
//                    suites.add(value);
//                }
//            } catch (Exception e) {
//                // Skip unreadable fields
//            }
//        }
//        return suites;
//    }

    /**
     * Resolves a human-readable name from Bouncy Castle's CipherSuite class constants.
     */
    private static String getCipherSuiteName(int code) {
        for (Field field : CipherSuite.class.getFields()) {
            try {
                if (field.getType() == int.class && field.getInt(null) == code) {
                    return field.getName();
                }
            } catch (Exception e) {
                // Ignore
            }
        }
        return "UNKNOWN_CIPHER_SUITE";
    }
}
