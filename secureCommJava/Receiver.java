import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.util.Arrays;
import java.util.Base64;

public class Receiver {

    private PrivateKey receiverPrivateKey;
    private PublicKey receiverPublicKey;
    private PublicKey senderPublicKey;
    private String message;
    private byte[] encryptedKey;
    private byte[] encryptedMessage;
    private byte[] macBytes;

    private static final SecureRandom secureRandom = new SecureRandom();
    private static final String RSA = "RSA";
    private static final String AES = "AES";

    // Method to generate RSA key pair for the receiver
    public void generateKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA);
        keyPairGenerator.initialize(2048, secureRandom);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        receiverPrivateKey = keyPair.getPrivate();
        receiverPublicKey = keyPair.getPublic();

        // Save receiver's key pair to files
        try (FileOutputStream receiverPrivateKeyFile = new FileOutputStream("./secureCommJava/receiver.private.key")) {
            receiverPrivateKeyFile.write(Base64.getEncoder().encode(receiverPrivateKey.getEncoded()));
        }

        try (FileOutputStream receiverPublicKeyFile = new FileOutputStream("./secureCommJava/receiver.public.key")) {
            receiverPublicKeyFile.write(Base64.getEncoder().encode(receiverPublicKey.getEncoded()));
        }
    }

    // Method to receive encrypted components from a file
    public void receiveMessage() throws Exception {
        try (BufferedReader br = new BufferedReader(new FileReader("./secureCommJava/Transmitted_Data"))) {
            encryptedMessage = Base64.getDecoder().decode(br.readLine());
            encryptedKey = Base64.getDecoder().decode(br.readLine());
            macBytes = Base64.getDecoder().decode(br.readLine());
        }
    }

    // Method to decrypt the received message
    public void decryptMessage() throws Exception {
        // Read sender's public key from file
        try (FileInputStream senderPublicKeyFile = new FileInputStream("./secureCommJava/sender.public.key")) {
            byte[] senderPublicKeyBytes = new byte[senderPublicKeyFile.available()];
            senderPublicKeyFile.read(senderPublicKeyBytes);

            byte[] decodedSenderPublicKey = Base64.getDecoder().decode(senderPublicKeyBytes);
            X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(decodedSenderPublicKey);

            KeyFactory keyFactory = KeyFactory.getInstance(RSA, "SunRsaSign");
            senderPublicKey = keyFactory.generatePublic(pubKeySpec);
        }

        // Decrypt the AES key using the receiver's private key
        Cipher rsaCipher = Cipher.getInstance(RSA);
        rsaCipher.init(Cipher.DECRYPT_MODE, receiverPrivateKey);
        byte[] decodedKey = rsaCipher.doFinal(encryptedKey);
        SecretKey aesKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");

        // Decrypt the message using the decrypted AES key
        Cipher aesCipher = Cipher.getInstance(AES);
        aesCipher.init(Cipher.DECRYPT_MODE, aesKey);
        byte[] decodedMessage = aesCipher.doFinal(encryptedMessage);
        message = new String(decodedMessage);

        // Verify MAC for data integrity
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(aesKey);
        byte[] calculatedMacBytes = mac.doFinal(message.getBytes());

        System.out.println("Mac Authentication: " + (Arrays.equals(macBytes, calculatedMacBytes) ? "successful" : "failed"));
    }

    // Method to get the decrypted message
    public String getMessage() {
        return message;
    }

    // Main method for testing
    public static void main(String[] args) throws Exception {
        Receiver receiver = new Receiver();
        receiver.generateKeyPair();
        receiver.receiveMessage();
        receiver.decryptMessage();
        System.out.println("Received Message: " + receiver.getMessage());
    }
}
