package encrypt;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;

public class Main {
    public static void main(String[] args) {
        try {
            // Generate RSA KeyPair first
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            String receiverPublicKey = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());

            // Step 1: Generate AES key and IV
            GenerateKey.KeyIVPair keyIV = GenerateKey.generateKey();
            System.out.println("\nStep 1 - Generated AES Key and IV:");
            System.out.println("AES Key (Base64): " + keyIV.getKey());
            System.out.println("IV (Base64): " + keyIV.getIV());
            
            // Step 2: Encrypt payload with AES and encode with Base64
            String payload = "Hello, this is a secret message!";
            String encryptedPayload = encryptPayload.encrypt(payload, keyIV.getKey(), keyIV.getIV());
            System.out.println("\nStep 2 - Encrypted Payload:");
            System.out.println("Original: " + payload);
            System.out.println("Encrypted (Base64): " + encryptedPayload);
            
            // Step 3: Encrypt AES key and IV with RSA
            encryptingKeyIV.EncryptedKeyIV encryptedKeyIV = encryptingKeyIV.encryptKeyIV(
                receiverPublicKey, 
                keyIV.getKey(), 
                keyIV.getIV()
            );
            System.out.println("\nStep 3 - RSA Encrypted Key and IV:");
            System.out.println("RSA Public Key (Base64): " + receiverPublicKey);
            System.out.println("Encrypted AES Key (Base64): " + encryptedKeyIV.getEncryptedKey());
            System.out.println("Encrypted IV (Base64): " + encryptedKeyIV.getEncryptedIV());
            
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
        }
    }
}