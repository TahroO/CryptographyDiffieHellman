import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

public class Alice extends Operator {
    public static void main(String[] args) throws Exception {

        Alice alice = new Alice();

        // Diffie-Hellman parameters
        BigInteger p = alice.getPrimeMod(); // Prime modulus
        BigInteger g = alice.getGBase();  // Base (generator)

        // Alice chooses a random private key
//        SecureRandom random = new SecureRandom();
//        BigInteger a = new BigInteger(128, random).mod(p); // Private key
        BigInteger a = alice.generatePrivateKey(p, alice.getNumBits());


//        BigInteger A = g.modPow(a, p);                              // Public key

        BigInteger A = alice.generatePublicKey(p, g, a);


        // Start server

        ServerSocket serverSocket = new ServerSocket(5000);

        System.out.println("Alice: Waiting for Bob...");
        Socket socket = serverSocket.accept();
        System.out.println("Alice: Connected to Bob.");

        DataInputStream in = new DataInputStream(socket.getInputStream());
        DataOutputStream out = new DataOutputStream(socket.getOutputStream());

        // Send public key A to Bob
        out.writeUTF(A.toString());
        System.out.println("Alice: Sent public key A = " + A);

        // Receive public key B from Bob
        BigInteger B = new BigInteger(in.readUTF());
        System.out.println("Alice: Received public key B = " + B);

        // Verify shared secret using DiscreteLogarithmSolver
        // Todo this does not work!
        DiscreteLogarithmSolver solver = new DiscreteLogarithmSolver();
        BigInteger verifiedSecret = solver.solve(g, B, p).modPow(a, p);
        System.out.println("Alice: Verified shared secret = " + verifiedSecret);

        // Compute shared secret
        BigInteger sharedSecret = B.modPow(a, p);
        System.out.println("Alice: Shared secret = " + sharedSecret);

        // Encrypt a message for Bob
        // we need multiples of 16 bytes messages here as we are using 16 byte key
        byte[] aesKey = alice.deriveAESKey(sharedSecret); // Ensure key is 16 bytes
        System.out.println("Alice: padded AES key = " + Arrays.toString(aesKey));
        SecretKeySpec keySpec = new SecretKeySpec(aesKey, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");

        String aliceMessage = "RSA is my kind of small talk...!";
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        byte[] plaintext = aliceMessage.getBytes();
        byte[] ciphertext = cipher.doFinal(plaintext);

        // Send encrypted message to Bob
        out.writeInt(ciphertext.length);
        System.out.println("Alice: encrypted message: " + alice.byteArrayToHex(ciphertext));
        out.write(ciphertext);
        System.out.println("Alice: Sent encrypted message to Bob.");

        // Receive encrypted message from Bob
        int bobCiphertextLength = in.readInt();
        byte[] bobCiphertext = new byte[bobCiphertextLength];
        in.readFully(bobCiphertext);

        // Decrypt Bob's message
        cipher.init(Cipher.DECRYPT_MODE, keySpec);
        byte[] decryptedBobMessage = cipher.doFinal(bobCiphertext);
        System.out.println("Alice: Decrypted message from Bob: " + new String(decryptedBobMessage).trim());


        // close connection
        socket.close();
        serverSocket.close();
    }

}
