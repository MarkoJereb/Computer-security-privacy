package isp.secrecy;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.KeyGenerator;
import java.security.Key;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;

/**
 * TASK:
 * Assuming Alice and Bob know a shared secret key in advance, encrypt their messages
 * using AES in CBC mode to provide confidentiality. Perform ten request-reply rounds:
 * Alice sends one encrypted message and Bob sends one encrypted reply in each round
 * (twenty encrypted messages in total). Both agents must decrypt and display received messages.
 * This exercise does not provide message authentication.
 * <p>
 * https://docs.oracle.com/en/java/javase/21/docs/api/java.base/javax/crypto/Cipher.html
 * https://docs.oracle.com/en/java/javase/21/docs/api/java.base/javax/crypto/spec/IvParameterSpec.html
 */
public class A1AESInCBCMode {
    public static void main(String[] args) throws Exception {
        // STEP 1: Alice and Bob beforehand agree upon a cipher algorithm and a shared secret key
        // Both agents can access this shared key from the enclosing method
        final Key key = KeyGenerator.getInstance("AES").generateKey();

        // STEP 2: Setup communication
        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                final String message = "I love you Bob. Kisses, Alice.";
                /* Alice creates, encrypts and sends a message to Bob. Bob replies to the message.
                 * Repeat for ten request-reply rounds.
                 *
                 * Use a fresh, unpredictable IV for every encryption, including Bob's replies.
                 * Send the IV along with the ciphertext; it need not be secret.
                 * A cipher-generated IV can be accessed via cipher.getIV().
                 */
                final Cipher aes = Cipher.getInstance("AES/CBC/PKCS5Padding");

                for (int i = 0; i < 10; i++) {
                    // Encrypt with a fresh IV (the cipher generates a random one on init)
                    aes.init(Cipher.ENCRYPT_MODE, key);
                    final byte[] ct = aes.doFinal(message.getBytes(StandardCharsets.UTF_8));
                    final byte[] iv = aes.getIV();

                    print("Round %d, sending: %s", i + 1, message);
                    send("bob", iv);
                    send("bob", ct);

                    // Receive and decrypt Bob's reply
                    final byte[] replyIv = receive("bob");
                    final byte[] replyCt = receive("bob");

                    aes.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(replyIv));
                    final byte[] reply = aes.doFinal(replyCt);
                    print("Round %d, got reply: %s", i + 1, new String(reply, StandardCharsets.UTF_8));
                }

            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                /* Bob receives, decrypts and displays a message.
                 * Wrap the received IV bytes in IvParameterSpec for the init() call:
                 *
                 *   IvParameterSpec ivSpec = new IvParameterSpec(iv);
                 *   aes.init(Cipher.DECRYPT_MODE, key, ivSpec);
                 *
                 * Encrypt and send a reply using a fresh IV in each round.
                 */
                final Cipher aes = Cipher.getInstance("AES/CBC/PKCS5Padding");
                final String reply = "I love you too Alice. Kisses, Bob.";

                for (int i = 0; i < 10; i++) {
                    // Receive and decrypt Alice's message
                    final byte[] iv = receive("alice");
                    final byte[] ct = receive("alice");

                    aes.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
                    final byte[] pt = aes.doFinal(ct);
                    print("Round %d, got message: %s", i + 1, new String(pt, StandardCharsets.UTF_8));

                    // Encrypt the reply with a fresh IV
                    aes.init(Cipher.ENCRYPT_MODE, key);
                    final byte[] replyCt = aes.doFinal(reply.getBytes(StandardCharsets.UTF_8));
                    final byte[] replyIv = aes.getIV();

                    print("Round %d, sending reply: %s", i + 1, reply);
                    send("alice", replyIv);
                    send("alice", replyCt);
                }
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
