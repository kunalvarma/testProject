package encrypt;

import javax.crypto.Cipher;
import java.security.PublicKey;
import java.security.KeyFactory;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class encryptingKeyIV {
    private static final String RSA_ALGORITHM = "RSA/ECB/OAEPWithMD5AndMGF1Padding";

    public static class EncryptedKeyIV {
        private final String encryptedKey;
        private final String encryptedIV;

        public EncryptedKeyIV(String encryptedKey, String encryptedIV) {
            this.encryptedKey = encryptedKey;
            this.encryptedIV = encryptedIV;
        }

        public String getEncryptedKey() { return encryptedKey; }
        public String getEncryptedIV() { return encryptedIV; }
    }

    public static EncryptedKeyIV encryptKeyIV(String base64PublicKey, String aesKey, String iv) throws Exception {
        // Decode the public key from Base64
        byte[] publicKeyBytes = Base64.getDecoder().decode(base64PublicKey);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes));

        // Create RSA cipher instance
        Cipher rsaCipher = Cipher.getInstance(RSA_ALGORITHM);
        rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);

        // Encrypt AES key
        byte[] aesKeyBytes = Base64.getDecoder().decode(aesKey);
        byte[] encryptedKeyBytes = rsaCipher.doFinal(aesKeyBytes);
        String encryptedKey = Base64.getEncoder().encodeToString(encryptedKeyBytes);

        // Encrypt IV
        byte[] ivBytes = Base64.getDecoder().decode(iv);
        rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);  // Reinitialize cipher for IV encryption
        byte[] encryptedIVBytes = rsaCipher.doFinal(ivBytes);
        String encryptedIV = Base64.getEncoder().encodeToString(encryptedIVBytes);

        return new EncryptedKeyIV(encryptedKey, encryptedIV);
    }
}