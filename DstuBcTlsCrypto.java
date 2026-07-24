import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.DSTU7624Engine;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.tls.EncryptionAlgorithm;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.crypto.TlsCipher;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
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
        if (encryptionAlgorithm == EncryptionAlgorithm.AES_256_GCM) {
            System.out.println("[DSTU-BC-CRYPTO] Instantiate DSTU 7624 (with identical parameters) instead of AES_256_GCM");
            DstuBcTlsAEADCipherImpl encrypt = new DstuBcTlsAEADCipherImpl(this.createGCMMode(new DSTU7624Engine(128)), true);
            DstuBcTlsAEADCipherImpl decrypt = new DstuBcTlsAEADCipherImpl(this.createGCMMode(new DSTU7624Engine(128)), false);
            return new TlsAEADCipher(cryptoParams, encrypt, decrypt, 32, 16, 3, (AEADNonceGeneratorFactory) null);
        }
        return super.createCipher(cryptoParams, encryptionAlgorithm, macAlgorithm);
    }
}

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
