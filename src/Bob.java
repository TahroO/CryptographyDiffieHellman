import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.util.Arrays;

public class Bob extends Operator {
    public static void main(String[] args) throws Exception {

        Bob bob = new Bob();

        // Diffie-Hellman parameters
        BigInteger p = bob.getPrimeMod(); // Prime modulus
        BigInteger g = bob.getGBase();  // Base (generator)

        // Generate PrivateKey
        BigInteger b = bob.generatePrivateKey(p, bob.getNumBits());

        BigInteger B = bob.generatePublicKey(p, g, b);

        // Connect to Alice
        System.out.println("Bob: Connecting to Alice...");
        Socket socket = new Socket("localhost", 5008);
        System.out.println("Bob: Connected to Alice.");

        DataInputStream in = new DataInputStream(socket.getInputStream());
        DataOutputStream out = new DataOutputStream(socket.getOutputStream());

        // Send public key B to Alice
        out.writeUTF(B.toString());
        System.out.println("Bob: Sent public key B = " + B);

        // Receive public key A from Alice
        BigInteger A = new BigInteger(in.readUTF());
        System.out.println("Bob: Received public key A = " + A);


        // Compute shared secret
        BigInteger sharedSecret = A.modPow(b, p);
        System.out.println("Bob: Shared secret = " + sharedSecret);

        // Encrypt a message for Alice
        // we need multiples of 16 bytes messages here as we are using 16 byte key
        byte[] aesKey = bob.deriveAESKey(sharedSecret); // Ensure key is 16 bytes
        System.out.println("Bob: padded AES key = " + Arrays.toString(aesKey));
        SecretKeySpec keySpec = new SecretKeySpec(aesKey, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");

        String bobMessage = "Decrypt me! Iam a ciphered mess.";
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        byte[] plaintext = bobMessage.getBytes();
        byte[] ciphertext = cipher.doFinal(plaintext);

        // Send encrypted message to Alice
        out.writeInt(ciphertext.length);
        System.out.println("Bob: Encrypted message: " + bob.byteArrayToHex(ciphertext));
        out.write(ciphertext);
        System.out.println("Bob: Sent encrypted message to Alice.");

        // Receive encrypted message from Alice
        int aliceCiphertextLength = in.readInt();
        byte[] aliceCiphertext = new byte[aliceCiphertextLength];
        in.readFully(aliceCiphertext);

        // Decrypt Alice's message
        cipher.init(Cipher.DECRYPT_MODE, keySpec);
        byte[] decryptedAliceMessage = cipher.doFinal(aliceCiphertext);
        System.out.println("Bob: Decrypted message from Alice: " + new String(decryptedAliceMessage).trim());

        // close connection
        socket.close();
    }
}
