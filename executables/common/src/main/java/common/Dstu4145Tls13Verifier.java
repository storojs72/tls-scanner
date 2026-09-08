package common;

import org.bouncycastle.tls.crypto.Tls13Verifier;

import java.io.IOException;
import java.io.OutputStream;

public class Dstu4145Tls13Verifier implements Tls13Verifier {
    @Override
    public OutputStream getOutputStream() throws IOException {
        return null;
    }

    @Override
    public boolean verifySignature(byte[] bytes) throws IOException {
        System.out.println("Calling verifySignature in DSTU mode (TLS 1.3)");
        // Stub to by-pass CertificateVerify packet validation during handshaking
        return true;
    }
}