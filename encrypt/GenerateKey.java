package encrypt;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.GCMParameterSpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class GenerateKey {
    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH = 128;

    public static class KeyIVPair {
        private final String key;
        private final String iv;

        public KeyIVPair(String key, String iv) {
            this.key = key;
            this.iv = iv;
        }

        public String getKey() { return key; }
        public String getIV() { return iv; }
    }

    public static KeyIVPair generateKey() throws NoSuchAlgorithmException {
        // Generate AES 256 key
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey key = keyGen.generateKey();
        
        // Generate random IV (96 bits = 12 bytes)
        byte[] iv = new byte[12];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(iv);
        
        // Convert to Base64
        String encodedKey = Base64.getEncoder().encodeToString(key.getEncoded());
        String encodedIV = Base64.getEncoder().encodeToString(iv);
        
        return new KeyIVPair(encodedKey, encodedIV);
    }

    public static Cipher createCipher(int mode, String base64Key, String base64IV) throws Exception {
        byte[] decodedKey = Base64.getDecoder().decode(base64Key);
        byte[] decodedIV = Base64.getDecoder().decode(base64IV);
        
        SecretKey key = new SecretKeySpec(decodedKey, "AES");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, decodedIV);
        
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(mode, key, gcmSpec);
        
        return cipher;
    }
}