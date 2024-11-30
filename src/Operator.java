import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

public class Operator {

    // Diffie-Hellman parameters
    private final BigInteger primeMod = new BigInteger("23"); // Prime modulus
    private final BigInteger gBase = new BigInteger("5");  // Base (generator)
    private final int numBits = 2048;


    protected BigInteger generatePrivateKey(BigInteger p, int numBits){

        //Constructs a secure random number generator (RNG) implementing the default random number algorithm.

        SecureRandom random = new SecureRandom();

        // Constructs a randomly generated BigInteger, uniformly distributed over the range 0 to (2numBits - 1),
        // inclusive. The uniformity of the distribution assumes that a fair source of random bits is provided
        // in rnd. Note that this constructor always constructs a non-negative BigInteger.

        BigInteger privateKey = new BigInteger(numBits, random).mod(p); // Private key

        return privateKey;
    }


    protected BigInteger generatePublicKey(BigInteger p, BigInteger g, BigInteger privateKey) {

        return g.modPow(privateKey, p);
    }

    protected BigInteger getGBase() {
        return gBase;
    }

    protected BigInteger getPrimeMod() {
        return primeMod;
    }

    protected int getNumBits() {
        return numBits;
    }


    /**
     * Hash the shared secret (e.g., using SHA-256) and use the first 16 bytes of the hash as the AES key.
     * This approach avoids the need for manual padding and ensures a deterministic, consistent key.
     * @param sharedSecret
     * @return
     * @throws Exception
     *
     * https://www.tutorialspoint.com/java_cryptography/java_cryptography_message_digest.html
     *
     */
    protected byte[] deriveAESKey(BigInteger sharedSecret) throws Exception {
        // Hash the shared secret to derive a consistent AES key
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(sharedSecret.toString().getBytes());

        // Use the first 16 bytes of the hash as the AES key
        return Arrays.copyOf(hash, 16);
    }

}
