import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.agreement.ECDHCBasicAgreement;
import org.bouncycastle.crypto.digests.DSTU7564Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.engines.DSTU7624Engine;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.tls.*;
import org.bouncycastle.tls.crypto.*;
import org.bouncycastle.tls.crypto.impl.AEADNonceGeneratorFactory;
import org.bouncycastle.tls.crypto.impl.TlsAEADCipher;
import org.bouncycastle.tls.crypto.impl.TlsAEADCipherImpl;
import org.bouncycastle.tls.crypto.impl.bc.*;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.SecureRandom;

public class DstuBcTlsCrypto extends BcTlsCrypto {
    public DstuBcTlsCrypto(SecureRandom entropySource) {
        super(entropySource);
    }

    @Override
    public TlsCipher createCipher(TlsCryptoParameters cryptoParams, int encryptionAlgorithm, int macAlgorithm) throws IOException {
        if (encryptionAlgorithm == EncryptionAlgorithm.AES_128_GCM) {
            DstuBcTlsAEADCipherImpl encrypt = new DstuBcTlsAEADCipherImpl(this.createGCMMode(new DSTU7624Engine(128)), true);
            DstuBcTlsAEADCipherImpl decrypt = new DstuBcTlsAEADCipherImpl(this.createGCMMode(new DSTU7624Engine(128)), false);
            return new TlsAEADCipher(cryptoParams, encrypt, decrypt, 16, 16, 3, (AEADNonceGeneratorFactory) null);
        }
        if (encryptionAlgorithm == EncryptionAlgorithm.AES_256_GCM) {
            DstuBcTlsAEADCipherImpl encrypt = new DstuBcTlsAEADCipherImpl(this.createGCMMode(new DSTU7624Engine(128)), true);
            DstuBcTlsAEADCipherImpl decrypt = new DstuBcTlsAEADCipherImpl(this.createGCMMode(new DSTU7624Engine(128)), false);
            return new TlsAEADCipher(cryptoParams, encrypt, decrypt, 32, 16, 3, (AEADNonceGeneratorFactory) null);
        }
        return super.createCipher(cryptoParams, encryptionAlgorithm, macAlgorithm);
    }

    @Override
    public Digest createDigest(int cryptoHashAlgorithm) {
        if (cryptoHashAlgorithm == HashAlgorithm.sha384) {
            return new DstuSha384MockDigest();
        }
        if (cryptoHashAlgorithm == HashAlgorithm.sha256) {
            return new DstuSha256MockDigest();
        }
        return super.createDigest(cryptoHashAlgorithm);
    }

    @Override
    public TlsHash createHash(int cryptoHashAlgorithm) {
        if (cryptoHashAlgorithm == HashAlgorithm.sha384 || cryptoHashAlgorithm == HashAlgorithm.sha256) {
            return new DstuBcTlsHash(this, cryptoHashAlgorithm);
        }
        return super.createHash(cryptoHashAlgorithm);
    }

    @Override
    public TlsECDomain createECDomain(TlsECConfig ecConfig) {
        // Check if the handshake is currently establishing an ECDH flow via secp256r1
        if (ecConfig.getNamedGroup() == NamedGroup.x25519) {
            return new Dstu4145ECDomain(this);
        }

        // Otherwise, allow any other curves/handshakes to process natively without modification
        return super.createECDomain(ecConfig);
    }

    @Override
    public TlsCertificate createCertificate(byte[] encoding) throws IOException {
        return new Dstu4145TlsCertificate(this, encoding);
    }
}

class Dstu4145TlsCertificate extends BcTlsCertificate {
    public Dstu4145TlsCertificate(DstuBcTlsCrypto crypto, byte[] encoding) throws IOException {
        super(crypto, encoding);
    }

    @Override
    public Tls13Verifier createVerifier(int signatureScheme) throws IOException {
        return new Dstu4145Tls13Verifier();
    }

//    @Override
//    public TlsVerifier createVerifier(short signatureScheme) {
//        return new Dstu4145TlsVerifier();
//    }
}

class Dstu4145Tls13Verifier implements Tls13Verifier {
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

//class Dstu4145TlsVerifier implements TlsVerifier {
//    @Override
//    public TlsStreamVerifier getStreamVerifier(DigitallySigned digitallySigned) throws IOException {
//        return null;
//    }
//
//    @Override
//    public boolean verifyRawSignature(DigitallySigned digitallySigned, byte[] bytes) throws IOException {
//        System.out.println("Calling verifySignature in DSTU mode");
//        // Stub to by-pass CertificateVerify packet validation during handshaking
//        return true;
//    }
//}

// Substitutes x25519 to DSTU 4145 (257 bits)
class Dstu4145ECDomain implements TlsECDomain {
    protected final DstuBcTlsCrypto crypto;

    public Dstu4145ECDomain(DstuBcTlsCrypto crypto) {
        this.crypto = crypto;
    }

    public TlsAgreement createECDH() {
        return new BcDstu4145(this.crypto);
    }
}

/*
    Note that TlsAgreement API can be used differently during actual TLS handshaking.
    More specifically, the order of `receivePeerValue` invocation is not the same on client and on server.
*/
class BcDstu4145 implements TlsAgreement {
    protected final BcTlsCrypto crypto;
    protected final ECKeyPairGenerator generator;
    protected final ECDomainParameters dstuParams;
    protected ECPrivateKeyParameters privateKeyParameters;
    protected ECPublicKeyParameters publicKeyParameters;

    public BcDstu4145(BcTlsCrypto crypto) {
        this.crypto = crypto;
        this.generator = new ECKeyPairGenerator();

        // choose DSTU 4145 curve with 233-bits field size as it maps well to x25519 (ultimate shared secret has 31 bytes length)
        // and then generate key pair
        this.dstuParams = SharedTlsCryptoConfig.DSTU4145_CURVE_ID;
        this.privateKeyParameters = null;
        this.publicKeyParameters = null;
    }

    public byte[] generateEphemeral() throws IOException {
        generator.init(new ECKeyGenerationParameters(dstuParams, crypto.getSecureRandom()));
        AsymmetricCipherKeyPair localKeyPair = generator.generateKeyPair();

        // save private key
        privateKeyParameters = (ECPrivateKeyParameters) localKeyPair.getPrivate();

        // return public key to peer
        ECPublicKeyParameters publicKeyParameters = (ECPublicKeyParameters) localKeyPair.getPublic();

        return publicKeyParameters.getQ().getEncoded(true);
    }

    public void receivePeerValue(byte[] peerValue) throws IOException {
        if (peerValue != null) {
            this.publicKeyParameters = new ECPublicKeyParameters(this.dstuParams.getCurve().decodePoint(peerValue), this.dstuParams);
        } else {
            throw new TlsFatalAlert((short) 47);
        }
    }

    public TlsSecret calculateSecret() throws IOException {
        BcTlsSecret tlsSecret;
        try {
            ECDHCBasicAgreement agreement = new ECDHCBasicAgreement();
            agreement.init(privateKeyParameters);
            BigInteger sharedSecret = agreement.calculateAgreement(publicKeyParameters);
            byte[] sharedSecretBytes = BigIntegers.asUnsignedByteArray(sharedSecret);
            if (Arrays.areAllZeroes(sharedSecretBytes, 0, sharedSecretBytes.length)) {
                throw new TlsFatalAlert((short) 40);
            }

            tlsSecret = new BcTlsSecret(crypto, sharedSecretBytes);
        } finally {
            privateKeyParameters = null;
            publicKeyParameters = null;
        }
        return tlsSecret;
    }
}

// Substitutes Sha384 to Dstu7564_384
class DstuSha384MockDigest extends SHA384Digest {
    private final DSTU7564Digest dstu7564;

    public DstuSha384MockDigest() {
        this.dstu7564 = new DSTU7564Digest(384);
    }

    @Override
    public void reset() {
        // This is important, since internal TLS machinery may call it with nullable digest primitive
        if (dstu7564 == null) {
            return;
        }
        dstu7564.reset();
    }
}

// Substitutes Sha256 to Dstu7564_256
class DstuSha256MockDigest extends SHA256Digest {
    private final DSTU7564Digest dstu7564;

    public DstuSha256MockDigest() {
        this.dstu7564 = new DSTU7564Digest(256);
    }

    @Override
    public void reset() {
        // This is important, since internal TLS machinery may call it with nullable digest primitive
        if (dstu7564 == null) {
            return;
        }
        dstu7564.reset();
    }
}

// Boilerplate code
class DstuBcTlsHash implements TlsHash {
    private final BcTlsCrypto crypto;
    private final int cryptoHashAlgorithm;
    private final Digest digest;

    DstuBcTlsHash(BcTlsCrypto crypto, int cryptoHashAlgorithm) {
        this(crypto, cryptoHashAlgorithm, crypto.createDigest(cryptoHashAlgorithm));
    }

    private DstuBcTlsHash(BcTlsCrypto crypto, int cryptoHashAlgorithm, Digest digest) {
        this.crypto = crypto;
        this.cryptoHashAlgorithm = cryptoHashAlgorithm;
        this.digest = digest;
    }

    public void update(byte[] data, int offSet, int length) {
        this.digest.update(data, offSet, length);
    }

    public byte[] calculateHash() {
        byte[] rv = new byte[this.digest.getDigestSize()];
        this.digest.doFinal(rv, 0);
        return rv;
    }

    public TlsHash cloneHash() {
        return new DstuBcTlsHash(this.crypto, this.cryptoHashAlgorithm, this.crypto.cloneDigest(this.cryptoHashAlgorithm, this.digest));
    }

    public void reset() {
        this.digest.reset();
    }
}

// Boilerplate code
class DstuBcTlsAEADCipherImpl implements TlsAEADCipherImpl {
    private final boolean isEncrypting;
    private final AEADBlockCipher cipher;
    private KeyParameter key;

    public DstuBcTlsAEADCipherImpl(AEADBlockCipher cipher, boolean isEncrypting) {
        this.cipher = cipher;
        this.isEncrypting = isEncrypting;
    }

    public void setKey(byte[] key, int keyOff, int keyLen) {
        this.key = new KeyParameter(key, keyOff, keyLen);
    }

    public void init(byte[] nonce, int macSize) {
        this.cipher.init(this.isEncrypting, new AEADParameters(this.key, macSize * 8, nonce, (byte[]) null));
    }

    public int getOutputSize(int inputLength) {
        return this.cipher.getOutputSize(inputLength);
    }

    public int doFinal(byte[] additionalData, byte[] input, int inputOffset, int inputLength, byte[] output, int outputOffset) throws IOException {
        if (!Arrays.isNullOrEmpty(additionalData)) {
            this.cipher.processAADBytes(additionalData, 0, additionalData.length);
        }

        int len = this.cipher.processBytes(input, inputOffset, inputLength, output, outputOffset);

        try {
            len += this.cipher.doFinal(output, outputOffset + len);
            return len;
        } catch (InvalidCipherTextException e) {
            throw new TlsFatalAlert((short) 20, e);
        }
    }
}
