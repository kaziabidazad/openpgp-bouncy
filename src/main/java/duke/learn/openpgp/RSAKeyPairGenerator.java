package duke.learn.openpgp;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;
import java.util.Date;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;

/**
 * A simple utility class that generates a RSA PGPPublicKey/PGPSecretKey pair.
 * 
 * Where identity is the name to be associated with the public key. The keys are
 * placed in the files pub.[asc|bpg] and secret.[asc|bpg].
 */
public class RSAKeyPairGenerator {

    private RSAKeyPairGenerator() {
    }

    /**
     * 
     * @param secretOut  Secret Key Destination Output stream
     * @param publicOut  Public Key Destination Output stream
     * @param pair       The generated Key Pair {@link KeyPair}
     * @param identity   The Identity to bind with the secret key
     * @param passPhrase The password to bind with the secret key
     * @param armor      Whether they Key should be armored
     * @throws IOException
     * @throws InvalidKeyException
     * @throws NoSuchProviderException
     * @throws SignatureException
     * @throws PGPException
     */
    private static void exportKeyPair(OutputStream secretOut, OutputStream publicOut, KeyPair pair, String identity,
	    char[] passPhrase, boolean armor)
	    throws IOException, InvalidKeyException, NoSuchProviderException, SignatureException, PGPException {
	if (armor) {
	    secretOut = new ArmoredOutputStream(secretOut);
	}

	// Create a Hash Calculator for checksum
	PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);
	// Generate the actual PGP key pair
	PGPKeyPair keyPair = new JcaPGPKeyPair(PGPPublicKey.RSA_GENERAL, pair, new Date());
	PGPSecretKey secretKey = new PGPSecretKey(PGPSignature.DEFAULT_CERTIFICATION, keyPair, identity, sha1Calc, null,
		null, new JcaPGPContentSignerBuilder(keyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA512),
		new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.CAST5, sha1Calc).setProvider("BC")
			.build(passPhrase));

	// Write the secret key
	secretKey.encode(secretOut);

	secretOut.close();

	if (armor) {
	    publicOut = new ArmoredOutputStream(publicOut);
	}

	PGPPublicKey key = secretKey.getPublicKey();
	// Write the public key
	key.encode(publicOut);

	publicOut.close();
    }

    public static void generateKeyPair(String publicKeyFilePath, String privateKeyFilePath, String identity,
	    String password) {
	// Set Bouncy Castle as the Security Provider
	Security.addProvider(new BouncyCastleProvider());
	// Get a Key-Pair Generator Instance using RSA Algo with 4096 bits for better
	// security
	try {
	    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
	    keyPairGenerator.initialize(4096);

	    // Now get the key pair
	    KeyPair keyPair = keyPairGenerator.generateKeyPair();
	    exportKeyPair(new FileOutputStream(privateKeyFilePath), new FileOutputStream(publicKeyFilePath), keyPair,
		    identity, password.toCharArray(), true);
	} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
	    // TODO Auto-generated catch block
	    e.printStackTrace();
	} catch (InvalidKeyException e) {
	    // TODO Auto-generated catch block
	    e.printStackTrace();
	} catch (SignatureException e) {
	    // TODO Auto-generated catch block
	    e.printStackTrace();
	} catch (FileNotFoundException e) {
	    // TODO Auto-generated catch block
	    e.printStackTrace();
	} catch (IOException e) {
	    // TODO Auto-generated catch block
	    e.printStackTrace();
	} catch (PGPException e) {
	    // TODO Auto-generated catch block
	    e.printStackTrace();
	}

    }

}
