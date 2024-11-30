import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class SymmetricDecrypter {
    public static void main(String[] args) throws Exception {
        // the ciphertext string to decrypt
        // we assume this to be in hex
        String hexCipherText = "366a02d0ddc4bbeb60aca7951955a0e971a5f247c9858aee6de033bb73399ff7c27ec8b4f924dfe82bb629a1d6f7ae14f991728c0d091b29390d9a048339614d14877f19896f4e3e24b1fd675155faa0269d4efe91debb29b2e25cc6be1459f9a9d9a29baeee707b426ede342f15888f791dce9e3c287c63489da0f99478734f9b8192846e6636250fa525d1ebb731ee50d8512b142ff3b63897980e1226b4651f273f066e98e4dbce013efa328b7e9463f1f985b9e7cd9a38062d92bccfc159207ab7ff712d7cc9b1408f40b9be3658b7f3de9be60c1598dde293b3408b38cbcfcd93350158be3f20b5a94a57bfb995fc390dcf3f59e8a4ceccc5e33cae37ea24cd3821fa1b96adf86b5058fe048bc8baebd1777389f2dee5285474e98ea9449b3c2858660c27f15928c3b8d84eb231aed92483be04b29b26a0e8f3df0eff8ee1d36279da90abd71e3e1338e362b1904575703656120dbbc53cc1d5528a43da3eeb674119e3721fe26bf512d45a92d9";

        // convert the ciphertext hex string to bytes
        byte[] cipherText = Utils.hexStringToByteArray(hexCipherText);

        // the decryption key
        // to actually use AES we need 16 bytes keys
        String keyString = "TaUfxxedMKJ2xUfK";

        byte[] keyBytes = keyString.getBytes();

        // create AES key
        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");

        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");

        System.out.println("Cipher text: " + Utils.toHex(cipherText));

        // decryption
        byte[] plainText = new byte[cipherText.length];

        // initialize decrypt mode
        cipher.init(Cipher.DECRYPT_MODE, key);

        int ptLength = cipher.update(cipherText, 0, cipherText.length, plainText, 0);

        ptLength += cipher.doFinal(plainText, ptLength);

//        System.out.println("Plain text : " + bytesToHex(plainText) + " bytes: " + ptLength);
        System.out.println("Plain text: " + Utils.toHex(plainText) + " bytes: " + ptLength);

        // plain text in as new String without hex
        System.out.println("Plain text as string: " + new String(plainText).trim());
    }

}
