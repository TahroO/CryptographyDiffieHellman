import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.util.Arrays;

public class Eve extends Operator{
    public static void main(String[] args) throws Exception {
        Eve eve = new Eve();

        BigInteger p = eve.getPrimeMod(); // Prime modulus
        BigInteger g = eve.getGBase();  // Base (generator)

        // Generate KEY EVE
        BigInteger e = eve.generatePrivateKey(p, eve.getNumBits());
        BigInteger E = eve.generatePublicKey(p, g, e);

        //HANDSHAKE
        System.out.println("### HANDSHAKE ###");
        ServerSocket aliceServerSocket = new ServerSocket(5008);
        System.out.println("Alice: Waiting for Bob...");
        Socket socket = aliceServerSocket.accept();
        System.out.println("Alice: Connected to Bob.");

        System.out.println("Bob: Connecting to Alice...");
        Socket bobSocket = new Socket("localhost", 5005);
        System.out.println("Bob: Connected to Alice.");

        //INPUT OUTPUT
        //What comes and goes to bob
        DataInputStream aliceIn = new DataInputStream(socket.getInputStream());
        DataOutputStream aliceOut = new DataOutputStream(socket.getOutputStream());
        //What comes from and goes to alice
        DataInputStream bobIn = new DataInputStream(bobSocket.getInputStream());
        DataOutputStream bobOut = new DataOutputStream(bobSocket.getOutputStream());

        //SHARE PUBLIC
        System.out.println("### SHARE PUBLIC ###");
        aliceOut.writeUTF(E.toString());
        System.out.println("Alice: Sent public key A = " + E);

        bobOut.writeUTF(E.toString());
        System.out.println("Bob: Sent public key B = " + E);

        //RECEIVE PUBLIC
        BigInteger B = new BigInteger(aliceIn.readUTF());
        System.out.println("Alice: Received public key B = " + B);
        BigInteger A = new BigInteger(bobIn.readUTF());
        System.out.println("Bob: Received public key A = " + A);

        //SHARED SECRET
        System.out.println("### SHARED SECRET ###");
        BigInteger sharedSecretWithAlice = B.modPow(e, p);
        System.out.println("Alice: Shared secret = " + sharedSecretWithAlice);
        BigInteger sharedSecretWithBob = A.modPow(e, p);
        System.out.println("Bob: Shared secret = " + sharedSecretWithBob);


        //ENCRYPT FOR BOB
        System.out.println("### SECRETS WITH BOB ###");
        byte[] aesKeyAlice = eve.deriveAESKey(sharedSecretWithAlice); // Ensure key is 16 bytes
        System.out.println("Alice: padded AES key = " + Arrays.toString(aesKeyAlice));
        SecretKeySpec keySpec = new SecretKeySpec(aesKeyAlice, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");

        String messageForBob = "RSA is my kind of small talk...!";
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        byte[] plaintextForBob = messageForBob.getBytes();
        byte[] ciphertextForBob = cipher.doFinal(plaintextForBob);

        // Send encrypted message to Bob
        aliceOut.writeInt(ciphertextForBob.length);
        System.out.println("Alice: encrypted message: " + eve.byteArrayToHex(ciphertextForBob));
        aliceOut.write(ciphertextForBob);
        System.out.println("Alice: Sent encrypted message to Bob.");

        // Receive encrypted message from Bob
        int cipherFromBobLength = aliceIn.readInt();
        byte[] cipherFromBob = new byte[cipherFromBobLength];
        aliceIn.readFully(cipherFromBob);

        // Decrypt Bob's message
        cipher.init(Cipher.DECRYPT_MODE, keySpec);
        byte[] decryptedFromBob = cipher.doFinal(cipherFromBob);
        System.out.println("Alice: Decrypted message from Bob: " + new String(decryptedFromBob).trim());


        //ENCRYPT FOR ALICE
        System.out.println("### SECRETS WITH ALICE ###");
        // we need multiples of 16 bytes messages here as we are using 16 byte key
        byte[] aesKeyBob = eve.deriveAESKey(sharedSecretWithBob); // Ensure key is 16 bytes
        System.out.println("Bob: padded AES key = " + Arrays.toString(aesKeyBob));
        SecretKeySpec keySpecBob = new SecretKeySpec(aesKeyBob, "AES");

        Cipher cipherBob = Cipher.getInstance("AES/ECB/NoPadding");

        String messageForAlice = "Decrypt me! Iam a ciphered mess.";

        cipherBob.init(Cipher.ENCRYPT_MODE, keySpecBob);
        byte[] plaintextForAlice = messageForAlice.getBytes();
        byte[] ciphertextForALice = cipherBob.doFinal(plaintextForAlice);

        // Send encrypted message to Alice
        bobOut.writeInt(ciphertextForALice.length);
        System.out.println("Bob: Encrypted message: " + eve.byteArrayToHex(ciphertextForALice));
        bobOut.write(ciphertextForALice);
        System.out.println("Bob: Sent encrypted message to Alice.");

        // Receive encrypted message from Alice
        int cipherFromAliceLength = bobIn.readInt();
        byte[] cipherFromAlice = new byte[cipherFromAliceLength];
        bobIn.readFully(cipherFromAlice);

        // Decrypt Alice's message
        cipherBob.init(Cipher.DECRYPT_MODE, keySpecBob);
        byte[] decryptedFromAlice = cipherBob.doFinal(cipherFromAlice);
        System.out.println("Bob: Decrypted message from Alice: " + new String(decryptedFromAlice).trim());

        //CLOSE CONNECTIONS
        bobSocket.close();
        socket.close();
        aliceServerSocket.close();
    }
}



