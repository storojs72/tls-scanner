import org.bouncycastle.tls.DefaultTlsClient;
import org.bouncycastle.tls.TlsClientProtocol;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;
import org.bouncycastle.tls.TlsAuthentication;
import org.bouncycastle.tls.ServerOnlyTlsAuthentication;
import org.bouncycastle.tls.TlsServerCertificate;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.security.SecureRandom;

public class BouncyCastleTlsTest {
    public static void main(String[] args) {
        // Check if the user passed a host parameter
        if (args.length < 1) {
            System.out.println("Usage: java -cp \"lib/*:.\" BouncyCastleTlsTest <hostname>");
            System.out.println("Example: java -cp \"lib/*:.\" BouncyCastleTlsTest google.com");
            return;
        }

        // Grab the host from the command line arguments
        String host = args[0];
        int port = 443;

        System.out.println("Connecting to " + host + " on port " + port + "...");

        try (Socket socket = new Socket(host, port)) {
            // Initialize the Bouncy Castle Crypto backend
            BcTlsCrypto crypto = new BcTlsCrypto(new SecureRandom());

            // Set up the protocol handler
            TlsClientProtocol tlsClientProtocol = new TlsClientProtocol(
                socket.getInputStream(), 
                socket.getOutputStream()
            );

            // Connect using the Bouncy Castle DefaultTlsClient
            tlsClientProtocol.connect(new DefaultTlsClient(crypto) {
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


            // Use these wrapped streams for your encrypted I/O
            InputStream secureIn = tlsClientProtocol.getInputStream();
            OutputStream secureOut = tlsClientProtocol.getOutputStream();

            // Example: send an HTTP GET request
            String request = "GET / HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n";
            secureOut.write(request.getBytes());
            secureOut.flush();

            // Read the response
            int data = secureIn.read();
            while(data != -1) {
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
