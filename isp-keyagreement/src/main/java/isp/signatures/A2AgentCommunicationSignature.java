package isp.signatures;

import fri.isp.Agent;
import fri.isp.Environment;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;

/*
 * Assuming Alice and Bob know each other's authentic public key, exchange signed messages
 * using ECDSA. Complete ten request-reply rounds: Alice sends a signed message and Bob
 * sends a signed reply in each round. Each recipient verifies the signature and rejects
 * invalid messages. Signatures provide integrity and evidence of the signer, not secrecy.
 */
public class A2AgentCommunicationSignature {
    public static void main(String[] args) throws Exception{
        final Environment env = new Environment();

        // Create key pairs
        final KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(256);
        final KeyPair aliceKP = kpg.generateKeyPair();
        final KeyPair bobKP = kpg.generateKeyPair();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                /* creates a message, signs it,
                   and then sends the message, signature pair to bob
                   receive the message-signature pair, verify the signature
                   repeat 10 times
                 */
                for (int i = 0; i < 10; i++) {
                    // Sign and send
                    final String text = "Hello Bob, this is round " + (i + 1);
                    final byte[] msg = text.getBytes(StandardCharsets.UTF_8);

                    final Signature signer = Signature.getInstance("SHA256withECDSA");
                    signer.initSign(aliceKP.getPrivate());
                    signer.update(msg);
                    send("bob", msg);
                    send("bob", signer.sign());

                    // Receive Bob's reply and verify it
                    final byte[] reply = receive("bob");
                    final byte[] replySig = receive("bob");

                    final Signature verifier = Signature.getInstance("SHA256withECDSA");
                    verifier.initVerify(bobKP.getPublic());
                    verifier.update(reply);
                    if (!verifier.verify(replySig)) {
                        print("Invalid signature from Bob in round %d, rejecting.", i + 1);
                        return;
                    }
                    print("Round %d, verified reply: %s", i + 1, new String(reply, StandardCharsets.UTF_8));
                }
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                for (int i = 0; i < 10; i++) {
                    // Receive Alice's message and verify it
                    final byte[] msg = receive("alice");
                    final byte[] sig = receive("alice");

                    final Signature verifier = Signature.getInstance("SHA256withECDSA");
                    verifier.initVerify(aliceKP.getPublic());
                    verifier.update(msg);
                    if (!verifier.verify(sig)) {
                        print("Invalid signature from Alice in round %d, rejecting.", i + 1);
                        return;
                    }
                    print("Round %d, verified message: %s", i + 1, new String(msg, StandardCharsets.UTF_8));

                    // Sign and send the reply
                    final byte[] reply = ("Hello Alice, reply " + (i + 1)).getBytes(StandardCharsets.UTF_8);
                    final Signature signer = Signature.getInstance("SHA256withECDSA");
                    signer.initSign(bobKP.getPrivate());
                    signer.update(reply);
                    send("alice", reply);
                    send("alice", signer.sign());
                }
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
