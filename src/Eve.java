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

        // Generate PrivateKey BOB
        BigInteger b = eve.generatePrivateKey(p, eve.getNumBits());

        // Generate PrivateKey ALICE
        BigInteger a = eve.generatePrivateKey(p, eve.getNumBits());
        BigInteger A = eve.generatePublicKey(p, g, a);


        //ALICE
        ServerSocket aliceServerSocket = new ServerSocket(5008);
        Socket socket = aliceServerSocket.accept();


        // approach to start a different Server Thread to handel multiple sockets
        // see ClientHandler Class at the bottom here

//        ClientHandler clientHandler = new ClientHandler(socket);
//
//        new Thread(clientHandler).start();



        DataInputStream aliceIn = new DataInputStream(socket.getInputStream());
        DataOutputStream aliceOut = new DataOutputStream(socket.getOutputStream());

        aliceOut.writeUTF(A.toString());
        System.out.println(A.toString());
        System.out.println("Alice: Sent public key A = " + A);

        BigInteger B = new BigInteger(aliceIn.readUTF());
        System.out.println("Alice: Received public key B = " + B);

        BigInteger sharedSecret = B.modPow(a, p);
        System.out.println("Alice: Shared secret = " + sharedSecret);

        byte[] aesKeyAlice = eve.deriveAESKey(sharedSecret); // Ensure key is 16 bytes
        System.out.println("Alice: padded AES key = " + Arrays.toString(aesKeyAlice));
        SecretKeySpec keySpec = new SecretKeySpec(aesKeyAlice, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");

        String aliceMessage = "RSA is my kind of small talk...!";
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        byte[] plaintext = aliceMessage.getBytes();
        byte[] ciphertext = cipher.doFinal(plaintext);

        // Send encrypted message to Bob
        aliceOut.writeInt(ciphertext.length);
        System.out.println("Alice: encrypted message: " + eve.byteArrayToHex(ciphertext));
        aliceOut.write(ciphertext);
        System.out.println("Alice: Sent encrypted message to Bob.");

        // Receive encrypted message from Bob
        int bobCiphertextLength = aliceIn.readInt();
        byte[] bobCiphertext = new byte[bobCiphertextLength];
        aliceIn.readFully(bobCiphertext);

        // Decrypt Bob's message
        cipher.init(Cipher.DECRYPT_MODE, keySpec);
        byte[] decryptedBobMessage = cipher.doFinal(bobCiphertext);
        System.out.println("Alice: Decrypted message from Bob: " + new String(decryptedBobMessage).trim());

        socket.close();
        aliceServerSocket.close();


        //BOB
        Socket bobSocket = new Socket("localhost", 5005);
        DataInputStream bobIn = new DataInputStream(bobSocket.getInputStream());
        DataOutputStream bobOut = new DataOutputStream(bobSocket.getOutputStream());
        bobOut.writeUTF(B.toString());
        System.out.println(bobIn.readUTF());
        System.out.println("Bob: Sent public key B = " + B);

        BigInteger Anew = new BigInteger(bobIn.readUTF());
        System.out.println("Bob: Received public key A = " + Anew);

        // Verify shared secret using DiscreteLogarithmSolver

        // Compute shared secret
        BigInteger sharedSecretBob = Anew.modPow(b, p);

        System.out.println("Bob: Shared secret = " + sharedSecretBob);

        // Encrypt a message for Alice
        // we need multiples of 16 bytes messages here as we are using 16 byte key
        byte[] aesKeyBob = eve.deriveAESKey(sharedSecretBob); // Ensure key is 16 bytes
        System.out.println("Bob: padded AES key = " + Arrays.toString(aesKeyBob));
        SecretKeySpec keySpecBob = new SecretKeySpec(aesKeyBob, "AES");

        Cipher cipherBob = Cipher.getInstance("AES/ECB/NoPadding");

        String bobMessage = "Decrypt me! Iam a ciphered mess.";

        cipherBob.init(Cipher.ENCRYPT_MODE, keySpecBob);
        byte[] plaintextBob = bobMessage.getBytes();
        byte[] ciphertextBob = cipherBob.doFinal(plaintextBob);

        // Send encrypted message to Alice
        bobOut.writeInt(ciphertextBob.length);
        System.out.println("Bob: Encrypted message: " + eve.byteArrayToHex(ciphertextBob));
        bobOut.write(ciphertextBob);
        System.out.println("Bob: Sent encrypted message to Alice.");

        // Receive encrypted message from Alice
        int aliceCiphertextLength = bobIn.readInt();
        byte[] aliceCiphertext = new byte[aliceCiphertextLength];
        bobIn.readFully(aliceCiphertext);

        // Decrypt Alice's message
        cipherBob.init(Cipher.DECRYPT_MODE, keySpecBob);
        byte[] decryptedAliceMessage = cipherBob.doFinal(aliceCiphertext);
        System.out.println("Bob: Decrypted message from Alice: " + new String(decryptedAliceMessage).trim());

        // close connection
        bobSocket.close();

    }

    // approach to handle different Sockets at a time
//    // ClientHandler class
//    private static class ClientHandler implements Runnable {
//        private final Socket clientSocket;
//
//        // Constructor
//        public ClientHandler(Socket socket)
//        {
//            this.clientSocket = socket;
//        }
//
//        public void run()
//        {
//            PrintWriter out = null;
//            BufferedReader in = null;
//            try {
//
//                // get the outputstream of client
//                out = new PrintWriter(
//                        clientSocket.getOutputStream(), true);
//
//                // get the inputstream of client
//                in = new BufferedReader(
//                        new InputStreamReader(
//                                clientSocket.getInputStream()));
//
//                String line;
//                while ((line = in.readLine()) != null) {
//
//                    // writing the received message from
//                    // client
//                    System.out.printf(
//                            " Sent from the client: %s\n",
//                            line);
//                    out.println(line);
//                }
//            }
//            catch (IOException e) {
//                e.printStackTrace();
//            }
//            finally {
//                try {
//                    if (out != null) {
//                        out.close();
//                    }
//                    if (in != null) {
//                        in.close();
//                        clientSocket.close();
//                    }
//                }
//                catch (IOException e) {
//                    e.printStackTrace();
//                }
//            }
//        }
//    }
}



