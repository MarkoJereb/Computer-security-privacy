package isp.keyagreement;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

/*
 * Implement the unauthenticated key exchange from the slides between Alice and Bob using
 * public-key encryption to establish a shared symmetric secret (not DH or ECDH alone).
 * Then Alice sends Bob a message encrypted with AES-GCM. Bob decrypts and displays it.
 * The public key is not authenticated, so the exchange is vulnerable to active attackers.
 */
public class A1AgentCommunicationKeyExchange {
    public static void main(String[] args) {
        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                // 1. Generate an RSA key pair and send the public key to Bob
                final KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
                send("bob", keyPair.getPublic().getEncoded());

                // 2. Receive the RSA-encrypted session key and decrypt it with the private key
                final byte[] encKey = receive("bob");
                final Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPPadding");
                rsa.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
                final SecretKeySpec aesKey = new SecretKeySpec(rsa.doFinal(encKey), "AES");
                print("Got the session key.");

                // 3. Send a message encrypted with AES-GCM
                final String message = "Hello Bob! This is our secret.";
                final Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
                aes.init(Cipher.ENCRYPT_MODE, aesKey);          // fresh random IV
                final byte[] ct = aes.doFinal(message.getBytes(StandardCharsets.UTF_8));
                send("bob", aes.getIV());
                send("bob", ct);
                print("Sent: %s", message);

            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                // 1. Receive Alice's public key
                final PublicKey alicePK = KeyFactory.getInstance("RSA")
                        .generatePublic(new X509EncodedKeySpec(receive("alice")));

                // 2. Generate a random AES session key and send it encrypted under Alice's public key
                final SecretKey aesKey = KeyGenerator.getInstance("AES").generateKey();
                final Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPPadding");
                rsa.init(Cipher.ENCRYPT_MODE, alicePK);
                send("alice", rsa.doFinal(aesKey.getEncoded()));

                // 3. Receive the IV and ciphertext, then decrypt and authenticate with GCM
                final byte[] iv = receive("alice");
                final byte[] ct = receive("alice");
                final Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
                aes.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(128, iv));
                final byte[] pt = aes.doFinal(ct);
                print("I got: %s", new String(pt, StandardCharsets.UTF_8));

            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
