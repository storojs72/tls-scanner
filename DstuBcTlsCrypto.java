import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.DSTU7564Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.engines.DSTU7624Engine;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.tls.EncryptionAlgorithm;
import org.bouncycastle.tls.HashAlgorithm;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.crypto.TlsCipher;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.TlsHash;
import org.bouncycastle.tls.crypto.impl.AEADNonceGeneratorFactory;
import org.bouncycastle.tls.crypto.impl.TlsAEADCipher;
import org.bouncycastle.tls.crypto.impl.TlsAEADCipherImpl;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;
import org.bouncycastle.util.Arrays;

import java.io.IOException;
import java.security.SecureRandom;

public class DstuBcTlsCrypto extends BcTlsCrypto {
    public DstuBcTlsCrypto(SecureRandom entropySource) {
        super(entropySource);
    }

    @Override
    public TlsCipher createCipher(TlsCryptoParameters cryptoParams, int encryptionAlgorithm, int macAlgorithm) throws IOException {
        if (encryptionAlgorithm == EncryptionAlgorithm.AES_128_GCM) {
            System.out.println("[DSTU-BC-CRYPTO.createCipher] Instantiate DSTU 7624 (with identical parameters) instead of AES_128_GCM");
            DstuBcTlsAEADCipherImpl encrypt = new DstuBcTlsAEADCipherImpl(this.createGCMMode(new DSTU7624Engine(128)), true);
            DstuBcTlsAEADCipherImpl decrypt = new DstuBcTlsAEADCipherImpl(this.createGCMMode(new DSTU7624Engine(128)), false);
            return new TlsAEADCipher(cryptoParams, encrypt, decrypt, 16, 16, 3, (AEADNonceGeneratorFactory) null);
        }
        if (encryptionAlgorithm == EncryptionAlgorithm.AES_256_GCM) {
            System.out.println("[DSTU-BC-CRYPTO.createCipher] Instantiate DSTU 7624 (with identical parameters) instead of AES_256_GCM");
            DstuBcTlsAEADCipherImpl encrypt = new DstuBcTlsAEADCipherImpl(this.createGCMMode(new DSTU7624Engine(128)), true);
            DstuBcTlsAEADCipherImpl decrypt = new DstuBcTlsAEADCipherImpl(this.createGCMMode(new DSTU7624Engine(128)), false);
            return new TlsAEADCipher(cryptoParams, encrypt, decrypt, 32, 16, 3, (AEADNonceGeneratorFactory) null);
        }
        return super.createCipher(cryptoParams, encryptionAlgorithm, macAlgorithm);
    }

    @Override
    public Digest createDigest(int cryptoHashAlgorithm) {
        if (cryptoHashAlgorithm == HashAlgorithm.sha384) {
            System.out.println("[DSTU-BC-CRYPTO.createDigest_384] Instantiate DSTU 7564 (with identical parameters) instead of SHA384");
            return new DstuSha384MockDigest();
        }
        if (cryptoHashAlgorithm == HashAlgorithm.sha256) {
            System.out.println("[DSTU-BC-CRYPTO.createDigest_256] Instantiate DSTU 7564 (with identical parameters) instead of SHA256");
            return new DstuSha256MockDigest();
        }
        return super.createDigest(cryptoHashAlgorithm);
    }

    @Override
    public TlsHash createHash(int cryptoHashAlgorithm) {
        if (cryptoHashAlgorithm == HashAlgorithm.sha384 || cryptoHashAlgorithm == HashAlgorithm.sha256) {
            System.out.println("[DSTU-BC-CRYPTO.createHash] Instantiate DSTU 7564 (with identical parameters) instead of SHA256/384");
            return new DstuBcTlsHash(this, cryptoHashAlgorithm);
        }
        return super.createHash(cryptoHashAlgorithm);
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
