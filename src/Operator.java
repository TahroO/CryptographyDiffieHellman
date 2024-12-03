import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

public class Operator {

    private final BigInteger primeMod = new BigInteger("23"); // Prime modulus
    private final BigInteger gBase = new BigInteger("5");  // Base (generator)
    private final int numBits = 2048;

    /**
     * Generate a private key using a secure random number for Diffie-Hellman key exchange
     *
     * @param p a prime number which participants agreed on for the modulo operation
     * @param numBits the length range of bits for the generated BigInteger return value
     * @return a computed private Key for Diffie-Hellman key exchange
     */

    protected BigInteger generatePrivateKey(BigInteger p, int numBits){

        //Constructs a secure random number generator (RNG) implementing the default random number algorithm.

        SecureRandom random = new SecureRandom();

        // Constructs a randomly generated BigInteger, uniformly distributed over the range 0 to (2numBits - 1),
        // inclusive. The uniformity of the distribution assumes that a fair source of random bits is provided
        // in rnd. Note that this constructor always constructs a non-negative BigInteger.

        BigInteger privateKey = new BigInteger(numBits, random).mod(p); // Private key

        return privateKey;
    }

    /**
     * Generate a public key for Diffie-Hellman key exchange
     *
     * @param p a prime number which participants agreed on for the modulo operation (should be the same which was used
     *          for the private key generation
     * @param g the base for the public key generation which participants agreed on
     * @param privateKey a generated private key for Diffie-Hellman key exchange
     * @return a computed public key for Diffie-Hellman key exchange
     */

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
     *
     * @param sharedSecret a BigInteger shared secret value from Diffie-Hellman Key Exchange
     * @return an array with the defined length filled with the first values of the hash from the parameter
     * @throws Exception
     *
     */

    protected byte[] deriveAESKey(BigInteger sharedSecret) throws Exception {
        // Hash the shared secret to derive a consistent AES key
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(sharedSecret.toString().getBytes());

        // Use the first 16 bytes of the hash as the AES key
        return Arrays.copyOf(hash, 16);
    }

    /**
     * Convert a provided byte[] into its hexadecimal format string representation
     *
     * @param a array of bytes representing a text
     * @return the computed hexValue string representation of the given inputText
     *
     */

    protected String byteArrayToHex(byte[] a) {
        StringBuilder sb = new StringBuilder(a.length * 2);
        for(byte b: a)
            sb.append(String.format("%02x", b));
        return sb.toString();
    }
}
