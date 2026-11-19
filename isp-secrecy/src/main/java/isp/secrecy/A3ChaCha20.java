package isp.secrecy;

import java.security.Key;

import javax.crypto.KeyGenerator;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.spec.ChaCha20ParameterSpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

/**
 * TASK:
 * Assuming Alice and Bob know a shared secret key in advance, encrypt their messages
 * using the ChaCha20 stream cipher to provide confidentiality. Perform ten request-reply rounds:
 * Alice sends one encrypted message and Bob sends one encrypted reply in each round
 * (twenty encrypted messages in total). Both agents must decrypt and display received messages.
 * This exercise does not provide message authentication.
 * <p>
 * https://docs.oracle.com/en/java/javase/21/docs/api/java.base/javax/crypto/Cipher.html
 * https://docs.oracle.com/en/java/javase/21/docs/api/java.base/javax/crypto/spec/ChaCha20ParameterSpec.html
 */
public class A3ChaCha20 {
    public static void main(String[] args) throws Exception {
        // STEP 1: Alice and Bob beforehand agree upon a cipher algorithm and a shared secret key
        // Both agents can access this shared key from the enclosing method
        final Key key = KeyGenerator.getInstance("ChaCha20").generateKey();

        // STEP 2: Setup communication
        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                final String message = "I love you Bob. Kisses, Alice.";
                /* Alice creates, encrypts and sends a message to Bob. Bob replies to the message.
                 * Repeat for ten request-reply rounds.
                 *
                 * For this exercise, explicitly specify a 12-byte nonce and an initial block
                 * counter using ChaCha20ParameterSpec. Use a fresh nonce for every encryption,
                 * including Bob's replies: nonces must not repeat under the shared key.
                 * Make the nonce and initial counter available to the receiver; neither is secret.
                 */
                final Cipher chacha = Cipher.getInstance("ChaCha20");
                final SecureRandom random = new SecureRandom();
                final int counter = 1; // initial block counter, not secret

                for (int i = 0; i < 10; i++) {
                    // Fresh 12-byte nonce for every message
                    final byte[] nonce = new byte[12];
                    random.nextBytes(nonce);

                    chacha.init(Cipher.ENCRYPT_MODE, key, new ChaCha20ParameterSpec(nonce, counter));
                    final byte[] ct = chacha.doFinal(message.getBytes(StandardCharsets.UTF_8));

                    print("Round %d, sending: %s", i + 1, message);
                    send("bob", nonce);
                    send("bob", ByteBuffer.allocate(4).putInt(counter).array());
                    send("bob", ct);

                    // Receive and decrypt Bob's reply
                    final byte[] replyNonce = receive("bob");
                    final int replyCounter = ByteBuffer.wrap(receive("bob")).getInt();
                    final byte[] replyCt = receive("bob");

                    chacha.init(Cipher.DECRYPT_MODE, key, new ChaCha20ParameterSpec(replyNonce, replyCounter));
                    final byte[] reply = chacha.doFinal(replyCt);
                    print("Round %d, got reply: %s", i + 1, new String(reply, StandardCharsets.UTF_8));
                }
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                // Receive, decrypt and display Alice's message, then encrypt and send
                // a reply with a fresh nonce. Repeat for ten request-reply rounds.
                final Cipher chacha = Cipher.getInstance("ChaCha20");
                final SecureRandom random = new SecureRandom();
                final String reply = "I love you too Alice. Kisses, Bob.";
                final int counter = 1;

                for (int i = 0; i < 10; i++) {
                    // Receive and decrypt Alice's message
                    final byte[] nonce = receive("alice");
                    final int aliceCounter = ByteBuffer.wrap(receive("alice")).getInt();
                    final byte[] ct = receive("alice");

                    chacha.init(Cipher.DECRYPT_MODE, key, new ChaCha20ParameterSpec(nonce, aliceCounter));
                    final byte[] pt = chacha.doFinal(ct);
                    print("Round %d, got message: %s", i + 1, new String(pt, StandardCharsets.UTF_8));

                    // Encrypt the reply with a fresh nonce
                    final byte[] replyNonce = new byte[12];
                    random.nextBytes(replyNonce);

                    chacha.init(Cipher.ENCRYPT_MODE, key, new ChaCha20ParameterSpec(replyNonce, counter));
                    final byte[] replyCt = chacha.doFinal(reply.getBytes(StandardCharsets.UTF_8));

                    print("Round %d, sending reply: %s", i + 1, reply);
                    send("alice", replyNonce);
                    send("alice", ByteBuffer.allocate(4).putInt(counter).array());
                    send("alice", replyCt);
                }
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
