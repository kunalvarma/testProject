package encrypt;

import javax.crypto.Cipher;
import java.util.Base64;

public class encryptPayload {
    public static String encrypt(String payload, String base64Key, String base64IV) {
        try {
            // Get cipher instance with our key and IV
            Cipher cipher = GenerateKey.createCipher(Cipher.ENCRYPT_MODE, base64Key, base64IV);
            
            // Encrypt the payload
            byte[] encryptedBytes = cipher.doFinal(payload.getBytes("UTF-8"));
            
            // Encode to Base64
            return Base64.getEncoder().encodeToString(encryptedBytes);
            
        } catch (Exception e) {
            throw new RuntimeException("Encryption failed: " + e.getMessage(), e);
        }
    }
}