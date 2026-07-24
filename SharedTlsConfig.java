import org.bouncycastle.tls.CipherSuite;

public class SharedTlsConfig {
    public static final int[] MY_CUSTOM_SUITES = new int[]{
            CipherSuite.TLS_AES_256_GCM_SHA384,            // TLS 1.3
            CipherSuite.TLS_AES_128_GCM_SHA256,            // TLS 1.3
            CipherSuite.TLS_CHACHA20_POLY1305_SHA256,      // TLS 1.3
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, // TLS 1.2 (ECDHE-RSA)
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, // TLS 1.2 (ECDHE-RSA)
            CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,   // TLS 1.2 (DHE-RSA)
            CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,   // TLS 1.2 (DHE-RSA)
            CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384,       // TLS 1.2 (Plain RSA)
            CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,       // TLS 1.2 (Plain RSA)
    };
}
