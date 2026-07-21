import org.bouncycastle.tls.DefaultTlsClient;
import org.bouncycastle.tls.TlsClientProtocol;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;
import org.bouncycastle.tls.TlsAuthentication;
import org.bouncycastle.tls.ServerOnlyTlsAuthentication;
import org.bouncycastle.tls.TlsServerCertificate;
import org.bouncycastle.tls.SecurityParameters;
import org.bouncycastle.tls.TlsClientContext;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.security.SecureRandom;

public class TlsTest {

    // We will use this to safely reference the connection context outside the subclass
    private static TlsClientContext savedContext = null;

    public static void main(String[] args) {
        // Check if the user passed a host parameter
        if (args.length < 2) {
            System.out.println("Usage: java -cp \"lib/*:out\" TlsTest <hostname> <port>");
            System.out.println("Example: java -cp \"lib/*:out\" TlsTest google.com 443");
            return;
        }

        // Grab the host and port from the command line arguments
        String host = args[0];
        int port = 0;
        try {
            port = Integer.parseInt(args[1]);
        } catch (Exception e) {
            System.out.println("Specified port is invalid");
            e.printStackTrace();
            System.exit(1);
        }

        System.out.println("Connecting to " + host + " on port " + port + "...");

        try (Socket socket = new Socket(host, port)) {
            // Initialize the Bouncy Castle Crypto backend
            BcTlsCrypto crypto = new BcTlsCrypto(new SecureRandom());

            // Set up the protocol handler
            TlsClientProtocol tlsClientProtocol = new TlsClientProtocol(socket.getInputStream(), socket.getOutputStream());

            // Connect using the Bouncy Castle DefaultTlsClient
            tlsClientProtocol.connect(new DefaultTlsClient(crypto) {
                @Override
                public void init(TlsClientContext context) {
                    super.init(context);
                    // Capture the context securely when the client initializes
                    savedContext = context;
                }

                @Override
                public TlsAuthentication getAuthentication() {
                    return new ServerOnlyTlsAuthentication() {
                        @Override
                        public void notifyServerCertificate(TlsServerCertificate serverCertificate) {
                            System.out.println("Handshake successful! Server certificate received.");
                        }
                    };
                }
            });


            // --- EXTRACT CIPHER SUITE INFO SAFELY ---
            if (savedContext != null && savedContext.getSecurityParameters() != null) {
                SecurityParameters secParams = savedContext.getSecurityParameters();
                int suiteCode = secParams.getCipherSuite();

                System.out.println("\n========================================");
                System.out.println("Negotiated Cipher Suite: " + "(0x" + Integer.toHexString(suiteCode).toUpperCase() + ")");
                System.out.println("========================================\n");
            }
            // --------------------------------------

            // Use these wrapped streams for your encrypted I/O
            InputStream secureIn = tlsClientProtocol.getInputStream();
            OutputStream secureOut = tlsClientProtocol.getOutputStream();

            // Example: send an HTTP GET request
            String request = "GET / HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n";
            secureOut.write(request.getBytes());
            secureOut.flush();

            // Read the response
            int data = secureIn.read();
            while (data != -1) {
                System.out.print((char) data);
                data = secureIn.read();
            }

            // Close the TLS connection properly
            tlsClientProtocol.close();

        } catch (Exception e) {
            System.err.println("Connection failed for " + host);
            e.printStackTrace();
        }
    }
}
