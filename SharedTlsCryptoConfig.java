import org.bouncycastle.asn1.ua.DSTU4145NamedCurves;
import org.bouncycastle.asn1.ua.UAObjectIdentifiers;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.tls.CipherSuite;

public class SharedTlsCryptoConfig {
    // FIXME: TLS 1.2 is currently unsupported for DSTU-mode
    //  (it requires adding one more DSTU-abstractions layer to every specific key exchange: DH, ECDH, RSA)
    public static final int[] MY_CUSTOM_SUITES = new int[]{
            CipherSuite.TLS_AES_256_GCM_SHA384,            // TLS 1.3
            CipherSuite.TLS_AES_128_GCM_SHA256,            // TLS 1.3
            CipherSuite.TLS_CHACHA20_POLY1305_SHA256,      // TLS 1.3
//            CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, // TLS 1.2 (ECDHE-RSA)
//            CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, // TLS 1.2 (ECDHE-RSA)
//            CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,   // TLS 1.2 (DHE-RSA)
//            CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,   // TLS 1.2 (DHE-RSA)
//            CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384,       // TLS 1.2 (Plain RSA)
//            CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,       // TLS 1.2 (Plain RSA)
    };

    public static ECDomainParameters DSTU4145_CURVE_ID = ConfigUtils.getDstu4145Curve(ConfigUtils.Dstu4145Curve.M257);
}

class ConfigUtils {
    enum Dstu4145Curve {
        M163,
        M167,
        M173,
        M179,
        M191,
        M233,
        M257,
        M307,
        M367,
        M431,
    }

    // Relevant only for DSTU-mode TLS
    static ECDomainParameters getDstu4145Curve(Dstu4145Curve curveId) {
        return switch (curveId) {
            case M163 -> DSTU4145NamedCurves.getByOID(UAObjectIdentifiers.dstu4145le.branch("2.0"));
            case M167 -> DSTU4145NamedCurves.getByOID(UAObjectIdentifiers.dstu4145le.branch("2.1"));
            case M173 -> DSTU4145NamedCurves.getByOID(UAObjectIdentifiers.dstu4145le.branch("2.2"));
            case M179 -> DSTU4145NamedCurves.getByOID(UAObjectIdentifiers.dstu4145le.branch("2.3"));
            case M191 -> DSTU4145NamedCurves.getByOID(UAObjectIdentifiers.dstu4145le.branch("2.4"));
            case M233 -> DSTU4145NamedCurves.getByOID(UAObjectIdentifiers.dstu4145le.branch("2.5"));
            case M257 -> DSTU4145NamedCurves.getByOID(UAObjectIdentifiers.dstu4145le.branch("2.6"));
            case M307 -> DSTU4145NamedCurves.getByOID(UAObjectIdentifiers.dstu4145le.branch("2.7"));
            case M367 -> DSTU4145NamedCurves.getByOID(UAObjectIdentifiers.dstu4145le.branch("2.8"));
            case M431 -> DSTU4145NamedCurves.getByOID(UAObjectIdentifiers.dstu4145le.branch("2.9"));
        };
    }
}
