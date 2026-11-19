package isp.secrecy;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Implement a brute force key search (exhaustive key search) if you know that the
 * message is:
 * "I would like to keep this text confidential Bob. Kind regards, Alice."
 * <p>
 * Assume the message was encrypted with "DES/ECB/PKCS5Padding".
 * Also assume that the key was poorly chosen. In particular, as an attacker,
 * you are certain that all bytes in the key, with the exception of the last three bytes,
 * have been set to 0.
 * <p>
 * A DES key is represented by 8 bytes, but only 56 bits affect encryption; the remaining
 * bits are parity bits. Varying the last three bytes produces 2^24 byte representations
 * but only 2^21 effective keys. Any equivalent key that correctly decrypts the ciphertext
 * is acceptable; it need not match the original key byte for byte.
 * <p>
 * In main(), generate a demonstration key with the stated restriction, encrypt the supplied
 * message with DES/ECB/PKCS5Padding, and call bruteForceKey(). Verify that the returned key
 * decrypts the ciphertext to the complete original message. Use UTF-8 for text conversion.
 * The search must use only its arguments and the stated key restriction, not the original key.
 * DES and ECB are used only for this teaching exercise, not as recommended encryption.
 * <p>
 * To manually specify a key, use {@link javax.crypto.spec.SecretKeySpec}.
 */
public class A4ExhaustiveSearch {
    public static void main(String[] args) throws Exception {
        final String message = "I would like to keep this text confidential Bob. Kind regards, Alice.";
        System.out.println("[MESSAGE] " + message);

        // Demonstration key: first five bytes are 0, last three are random
        final byte[] keyBytes = new byte[8];
        final byte[] tail = new byte[3];
        new SecureRandom().nextBytes(tail);
        System.arraycopy(tail, 0, keyBytes, 5, 3);

        final Cipher enc = Cipher.getInstance("DES/ECB/PKCS5Padding");
        enc.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(keyBytes, "DES"));
        final byte[] ct = enc.doFinal(message.getBytes(StandardCharsets.UTF_8));
        System.out.println("[CT] " + java.util.HexFormat.of().formatHex(ct));

        // Attack: uses only ct, message and the key restriction
        final long start = System.currentTimeMillis();
        final byte[] found = bruteForceKey(ct, message);
        final long ms = System.currentTimeMillis() - start;

        if (found == null) {
            System.out.println("[FAIL] No key found");
            return;
        }
        System.out.println("[KEY] " + java.util.HexFormat.of().formatHex(found) + " (" + ms + " ms)");

        // Verify the recovered key decrypts to the complete original message
        final Cipher dec = Cipher.getInstance("DES/ECB/PKCS5Padding");
        dec.init(Cipher.DECRYPT_MODE, new SecretKeySpec(found, "DES"));
        final String recovered = new String(dec.doFinal(ct), StandardCharsets.UTF_8);
        System.out.println("[DECRYPTED] " + recovered);
        System.out.println("[MATCH] " + recovered.equals(message));
    }

    /**
     * Recover an 8-byte representation of a key that decrypts ct to the known message.
     * Return null if no matching key exists within the restricted search space.
     */
    public static byte[] bruteForceKey(byte[] ct, String message) throws Exception {
        final byte[] expected = message.getBytes(StandardCharsets.UTF_8);

        // Cheap pre-check: decrypt only the first block (ECB blocks are independent)
        final Cipher firstBlockCipher = Cipher.getInstance("DES/ECB/NoPadding");
        final Cipher fullCipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        final byte[] ctFirst = Arrays.copyOf(ct, 8);
        final byte[] expectedFirst = Arrays.copyOf(expected, 8);

        final byte[] key = new byte[8]; // first five bytes stay 0

        // DES ignores the lowest bit of every byte (parity), so only the upper 7 bits
        // of each of the last three bytes matter: 2^21 effective keys.
        for (int i = 0; i < (1 << 21); i++) {
            key[5] = (byte) (((i >> 14) & 0x7F) << 1);
            key[6] = (byte) (((i >> 7) & 0x7F) << 1);
            key[7] = (byte) ((i & 0x7F) << 1);

            final SecretKeySpec ks = new SecretKeySpec(key, "DES");

            firstBlockCipher.init(Cipher.DECRYPT_MODE, ks);
            if (!Arrays.equals(firstBlockCipher.doFinal(ctFirst), expectedFirst)) {
                continue;
            }

            // First block matches: confirm with a full decryption
            try {
                fullCipher.init(Cipher.DECRYPT_MODE, ks);
                if (Arrays.equals(fullCipher.doFinal(ct), expected)) {
                    return key.clone();
                }
            } catch (BadPaddingException e) {
                // wrong key, keep searching
            }
        }

        return null;
    }
}
