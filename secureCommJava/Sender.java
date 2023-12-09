import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import java.io.*;
import java.util.Base64;

public class Sender {

    // Key pair for the sender
    private PrivateKey senderPrivateKey;
    private PublicKey senderPublicKey;

    // Public key for the receiver
    private PublicKey receiverPublicKey;

    // Message to be transmitted
    private String message;

    // Encrypted components
    private byte[] encryptedKey;
    private byte[] encryptedMessage;
    private byte[] macBytes;

    // Constants
    private static final SecureRandom secureRandom = new SecureRandom();
    private static final String RSA = "RSA";
    private static final String AES = "AES";

    // Method to generate RSA key pair for the sender
    public void generateKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA);
        keyPairGenerator.initialize(2048, secureRandom);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        senderPrivateKey = keyPair.getPrivate();
        senderPublicKey = keyPair.getPublic();

        // Save the keys to files
        writeKeyToFile(senderPrivateKey, "./secureCommJava/sender.private.key");
        writeKeyToFile(senderPublicKey, "./secureCommJava/sender.public.key");
    }

    // Set the message to be transmitted
    public void setMessage(String message) {
        this.message = message;
    }

    // Encrypt the message using AES and the receiver's public key
    public void encryptMessage() throws Exception {
        // Read the receiver's public key from file
        readPublicKeyFromFile("./secureCommJava/receiver.public.key");

        // Generate a random AES key
        SecretKey aesKey = generateAESKey();

        // Encrypt the message and the AES key using RSA
        encryptedMessage = encryptWithAES(aesKey, message);
        encryptedKey = encryptWithRSA(aesKey.getEncoded(), receiverPublicKey);

        // Generate a MAC for message integrity
        macBytes = generateMAC(aesKey, message);
    }

    // Send the encrypted components to a file
    public void sendMessage() throws Exception {
        try (FileOutputStream transmittedDataFile = new FileOutputStream("./secureCommJava/Transmitted_Data")) {
            writeDataToFile(transmittedDataFile, encryptedMessage);
            writeDataToFile(transmittedDataFile, encryptedKey);
            writeDataToFile(transmittedDataFile, macBytes);
        }
    }

    // Read a public key from a file
    private void readPublicKeyFromFile(String filePath) throws Exception {
        try (FileInputStream receiverPublicKeyFile = new FileInputStream(filePath)) {
            byte[] receiverPublicKeyBytes = new byte[receiverPublicKeyFile.available()];
            receiverPublicKeyFile.read(receiverPublicKeyBytes);

            // Decode the Base64-encoded public key
            byte[] decodedReceiverPublicKey = Base64.getDecoder().decode(receiverPublicKeyBytes);
            X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(decodedReceiverPublicKey);

            // Generate the public key from the decoded bytes
            KeyFactory keyFactory = KeyFactory.getInstance(RSA, "SunRsaSign");
            receiverPublicKey = keyFactory.generatePublic(pubKeySpec);
        }
    }

    // Write a key to a file
    private void writeKeyToFile(Key key, String filePath) throws IOException {
        try (FileOutputStream keyFile = new FileOutputStream(filePath)) {
            keyFile.write(Base64.getEncoder().encode(key.getEncoded()));
        }
    }

    // Write data to a file
    private void writeDataToFile(FileOutputStream fileOutputStream, byte[] data) throws IOException {
        fileOutputStream.write(Base64.getEncoder().encode(data));
        fileOutputStream.write('\n');
    }

    // Generate a random AES key
    private SecretKey generateAESKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(AES);
        keyGenerator.init(secureRandom);
        return keyGenerator.generateKey();
    }

    // Encrypt data with AES
    private byte[] encryptWithAES(SecretKey key, String data) throws Exception {
        Cipher aesCipher = Cipher.getInstance(AES);
        aesCipher.init(Cipher.ENCRYPT_MODE, key);
        return aesCipher.doFinal(data.getBytes());
    }

    // Encrypt data with RSA
    private byte[] encryptWithRSA(byte[] data, PublicKey key) throws Exception {
        Cipher rsaCipher = Cipher.getInstance(RSA);
        rsaCipher.init(Cipher.ENCRYPT_MODE, key);
        return rsaCipher.doFinal(data);
    }

    // Generate a MAC for data integrity
    private byte[] generateMAC(SecretKey key, String data) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(key);
        return mac.doFinal(data.getBytes());
    }

    // Main method for testing
    public static void main(String[] args) throws Exception {
        Sender sender = new Sender();
        sender.generateKeyPair();
        sender.setMessage("This is a secret message.");
        sender.encryptMessage();
        sender.sendMessage();
    }
}
