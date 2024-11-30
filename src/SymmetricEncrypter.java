import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class SymmetricEncrypter {

    public static void main(String[] args) throws Exception {

        // The text to be encrypted needs to be 16 / 32 ... long
        String inputString = "Hash it out, but make it salted.";

        // The key which should be used for encryption -> 16 bytes for AES
        String keyString = "qISen4PL!WGOK7TK";

        // convert the text to byte array
        byte[] inputBytes = inputString.getBytes();

        // convert the key to byte array
        byte[] keyBytes = keyString.getBytes();

        // create AES key
        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");

        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");

        System.out.println("input text: " + inputString);
        System.out.println("used key: " + keyString);

        // encryption
        byte[] cipherText = new byte[inputBytes.length];

        //initialize encryption mode
        cipher.init(Cipher.ENCRYPT_MODE, key);

        int ctLength = cipher.update(inputBytes, 0, inputBytes.length, cipherText, 0);

        ctLength += cipher.doFinal(cipherText, ctLength);

        System.out.println("cipher text: " + Utils.toHex(cipherText) + " bytes: " + ctLength);
    }
}