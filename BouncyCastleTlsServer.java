import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.security.Security;
import java.util.Arrays;

public class BouncyCastleTlsServer {
    public static void main(String[] args) throws Exception {
        // Grab keystore info from command line
        if (args.length < 3) {
            System.out.println("Usage: java -cp \"lib/*:out\" BouncyCastleTlsServer <path to p12 file> <keystore password> <port>");
            System.out.println("Example: java -cp \"lib/*:out\" BouncyCastleTlsServer bouncy-castle-tls/server.p12 password 8443");
            return;
        }
        String keyStore = args[0];
        String password = args[1];
        int port = 0;
        try {
            port = Integer.parseInt(args[2]);
        } catch (Exception e) {
            System.out.println("Specified port is invalid");
            e.printStackTrace();
            System.exit(1);
        }

        // Add Bouncy Castle as a security provider
        Security.addProvider(new BouncyCastleProvider());

        // System properties can be used to point to your keystore
        System.setProperty("javax.net.ssl.keyStore", keyStore);
        System.setProperty("javax.net.ssl.keyStorePassword", password);

        SSLServerSocketFactory ssf = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
        SSLServerSocket serverSocket = (SSLServerSocket) ssf.createServerSocket(port);

        System.out.println("Bouncy Castle TLS Server started on port " + port + " ...");

        String[] allSupportedSuites = serverSocket.getSupportedCipherSuites();
        System.out.println("Total enabled cipher suites: " + allSupportedSuites.length);
        System.out.println("Enabled suites: " + Arrays.toString(allSupportedSuites));


        while (true) {
            // Move the accept() outside the auto-closing try block so we can catch its specific errors
            try {
                Socket socket = serverSocket.accept();
                try (InputStream in = socket.getInputStream();
                     OutputStream out = socket.getOutputStream()) {

                    System.out.println("Client connected!");
                    out.write("HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello from BC!\n".getBytes());
                    out.flush();
                } catch (Exception e) {
                    System.err.println("Stream or handshake error: " + e.getMessage());
                }
            } catch (Exception e) {
                System.err.println("Accept error: " + e.getMessage());
            }
        }
    }
}
