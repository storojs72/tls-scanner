import org.bouncycastle.tls.DefaultTlsClient;
import org.bouncycastle.tls.TlsClientProtocol;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;
import org.bouncycastle.tls.TlsAuthentication;
import org.bouncycastle.tls.ServerOnlyTlsAuthentication;
import org.bouncycastle.tls.TlsServerCertificate;
import org.bouncycastle.tls.CipherSuite;

import java.io.IOException;
import java.lang.reflect.Field;
import java.net.Socket;
import java.security.SecureRandom;
import java.util.ArrayList;
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

        // 1. Gather all potential cipher suites known to Bouncy Castle
        List<Integer> allSuites = getAllKnownCipherSuites();
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
                tlsClientProtocol.connect(new DefaultTlsClient(crypto) {
                    @Override
                    public int[] getCipherSuites() {
                        return new int[]{ suiteCode };
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

    /**
     * Uses reflection to pull all raw integer cipher suites from Bouncy Castle.
     */
    private static List<Integer> getAllKnownCipherSuites() {
        List<Integer> suites = new ArrayList<>();
        for (Field field : CipherSuite.class.getFields()) {
            try {
                if (field.getType() == int.class) {
                    int value = field.getInt(null);
                    // Filter out signaling/scsv placeholders that aren't real ciphers
                    if (field.getName().contains("SCSV") || field.getName().equals("EMPTY_RENEGOTIATION_INFO_SCSV")) {
                        continue;
                    }
                    suites.add(value);
                }
            } catch (Exception e) {
                // Skip unreadable fields
            }
        }
        return suites;
    }

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
