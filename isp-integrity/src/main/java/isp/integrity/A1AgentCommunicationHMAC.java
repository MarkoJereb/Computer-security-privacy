package isp.integrity;

import java.security.Key;

import javax.crypto.KeyGenerator;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Mac;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * TASK:
 * Alice and Bob share a secret key. Authenticate their messages using HmacSHA256.
 * Complete ten request-reply rounds: Alice sends a message and Bob sends a reply
 * in each round (twenty authenticated messages in total).
 * Both agents must verify the received tag before displaying or using the message.
 * Reject an invalid tag; do not process the corresponding message.
 *
 * Send each message and its tag in the same agreed order. Use a separate Mac
 * instance for each agent and MessageDigest.isEqual to compare tags. For this
 * exercise, the shared key is generated here; do not send it over the channel.
 * HMAC does not encrypt messages or by itself prevent replay attacks.
 * <p>
 * https://docs.oracle.com/en/java/javase/21/docs/api/java.base/javax/crypto/Mac.html
 */
public class A1AgentCommunicationHMAC {
    public static void main(String[] args) throws Exception {
        /*
         * Alice and Bob share a secret session key that will be
         * used for hash based message authentication code.
         */
        final Key key = KeyGenerator.getInstance("HmacSHA256").generateKey();

        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                /*
                * Send ten UTF-8 messages with their tags. Receive and
                * verify Bob's reply in each round before displaying it.
                */
                final Mac mac = Mac.getInstance("HmacSHA256");
                mac.init(key);

                for (int i = 0; i < 10; i++) {
                    final byte[] msg = ("Hello Bob, round " + (i + 1)).getBytes(StandardCharsets.UTF_8);
                    final byte[] tag = mac.doFinal(msg);
                    // tag[0] ^= 1;          // TEMPORARY: corrupt tag to test rejection
                    send("bob", msg);
                    send("bob", tag);

                    final byte[] reply = receive("bob");
                    final byte[] replyTag = receive("bob");
                    if (!MessageDigest.isEqual(mac.doFinal(reply), replyTag)) {
                        print("Invalid tag from Bob in round %d, rejecting.", i + 1);
                        return;
                    }
                    print("Round %d, verified reply: %s", i + 1, new String(reply, StandardCharsets.UTF_8));
                }
            }
        });
        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                /*
                 * Receive and verify each message before displaying it.
                 * Send an authenticated reply in each of the ten rounds.
                 */
                final Mac mac = Mac.getInstance("HmacSHA256");
                mac.init(key);

                for (int i = 0; i < 10; i++) {
                    final byte[] msg = receive("alice");
                    final byte[] tag = receive("alice");
                    if (!MessageDigest.isEqual(mac.doFinal(msg), tag)) {
                        print("Invalid tag from Alice in round %d, rejecting.", i + 1);
                        return;
                    }
                    print("Round %d, verified message: %s", i + 1, new String(msg, StandardCharsets.UTF_8));

                    final byte[] reply = ("Hello Alice, reply " + (i + 1)).getBytes(StandardCharsets.UTF_8);
                    send("alice", reply);
                    send("alice", mac.doFinal(reply));
                }
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
