package isp;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.KeyGenerator;
import java.nio.charset.StandardCharsets;
import java.security.Key;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;

/**
 * TASK:
 * Assuming Alice and Bob know a shared secret key, secure the channel using
 * AES in GCM mode. Complete ten request-reply rounds: Alice sends one
 * encrypted message and Bob sends one encrypted reply in each round (twenty
 * encrypted messages in total). Both agents must decrypt and display the
 * messages they receive. Use a fresh IV for every encryption and send it
 * together with the ciphertext; the IV need not be secret.
 * <p>
 * https://docs.oracle.com/en/java/javase/21/docs/api/java.base/javax/crypto/Cipher.html
 * https://docs.oracle.com/en/java/javase/21/docs/api/java.base/javax/crypto/spec/GCMParameterSpec.html
 */
public class A1AgentCommunicationGCM {
    public static void main(String[] args) throws Exception {
        /*
         * Alice and Bob share a secret session key that will be
         * used for AES in GCM.
         */
        final Key key = KeyGenerator.getInstance("AES").generateKey();

        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                final String text = "I hope you get this message intact and in secret. Kisses, Alice.";
                final Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");

                for (int i = 0; i < 10; i++) {
                    // The cipher generates new IV on every init
                    aes.init(Cipher.ENCRYPT_MODE, key);
                    final byte[] ct = aes.doFinal(text.getBytes(StandardCharsets.UTF_8));
                    final byte[] iv = aes.getIV();

                    print("Round %d, sending: %s", i + 1, text);
                    send("bob", iv);
                    send("bob", ct);

                    final byte[] replyIv = receive("bob");
                    final byte[] replyCt = receive("bob");
                    aes.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, replyIv));
                    final byte[] reply = aes.doFinal(replyCt);
                    print("Round %d, got reply: %s", i + 1, new String(reply, StandardCharsets.UTF_8));
                }

            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                final String reply = "I got it, Alice. Kisses, Bob.";
                final Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");

                for (int i = 0; i < 10; i++) {
                    final byte[] iv = receive("alice");
                    final byte[] ct = receive("alice");
                    aes.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
                    final byte[] pt = aes.doFinal(ct);
                    print("Round %d, got message: %s", i + 1, new String(pt, StandardCharsets.UTF_8));

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
