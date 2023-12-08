/**
 * Demo class demonstrating the usage of Sender and Receiver to securely transmit and receive messages.
 */
public class Demo {
    public static void main(String[] args) throws Exception {
        // Messages to be transmitted and received
        String senderMessage = "Hello, world!";
        String receiverMessage = null;

        // Create instances of Sender and Receiver
        Sender sender = new Sender();
        Receiver receiver = new Receiver();

        // Generate key pairs for sender and receiver
        sender.generateKeyPair();
        receiver.generateKeyPair();

        // Set the message for the sender, encrypt, and send
        sender.setMessage(senderMessage);
        sender.encryptMessage();
        sender.sendMessage();

        // Receive the encrypted message, decrypt, and retrieve the message for the receiver
        receiver.receiveMessage();
        receiver.decryptMessage();
        receiverMessage = receiver.getMessage();

        // Display the original and received messages
        System.out.println("Sent message: " + senderMessage);
        System.out.println("Received message: " + receiverMessage);
    }
}
