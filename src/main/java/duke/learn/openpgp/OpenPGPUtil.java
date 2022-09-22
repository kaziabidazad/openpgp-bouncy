/**
 * 
 */
package duke.learn.openpgp;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchProviderException;
import java.util.Iterator;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;

/**
 * @author Kazi
 *
 */
public class OpenPGPUtil {

    /**
     * Search a secret key ring collection for a secret key corresponding to keyID
     * if it exists.
     * 
     * @param pgpSec a secret key ring collection.
     * @param keyID  keyID we want.
     * @param pass   passphrase to decrypt secret key with.
     * @return the private key.
     * @throws PGPException
     * @throws NoSuchProviderException
     */
    static PGPPrivateKey findSecretKey(PGPSecretKeyRingCollection pgpSec, long keyID, char[] pass)
	    throws PGPException, NoSuchProviderException {
	PGPSecretKey pgpSecKey = pgpSec.getSecretKey(keyID);

	if (pgpSecKey == null) {
	    return null;
	}

	return pgpSecKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(pass));
    }

    static PGPPublicKey readPublicKey(String publicKeyFile) throws FileNotFoundException, IOException, PGPException {
	PGPPublicKey pgpPublicKey = null;
	try (InputStream publicKeyInputStream = new BufferedInputStream(new FileInputStream(publicKeyFile))) {
	    pgpPublicKey = readPublicKey(publicKeyInputStream);
	    return pgpPublicKey;
	}

    }

    private static PGPPublicKey readPublicKey(InputStream publicKeyFileInputStream) throws IOException, PGPException {
	PGPPublicKeyRingCollection publicKeyRingCollection = new PGPPublicKeyRingCollection(
		PGPUtil.getDecoderStream(publicKeyFileInputStream), new JcaKeyFingerprintCalculator());

	//
	// Loop through the collection till we find a key suitable for
	// encryption. Probably want to be a bit smarter about this.
	//
	Iterator<PGPPublicKeyRing> keyRingIterator = publicKeyRingCollection.getKeyRings();
	while (keyRingIterator.hasNext()) {
	    PGPPublicKeyRing pgpPublicKeyRing = (PGPPublicKeyRing) keyRingIterator.next();
	    Iterator<PGPPublicKey> keyIterator = pgpPublicKeyRing.getPublicKeys();
	    while (keyIterator.hasNext()) {
		PGPPublicKey pgpPublicKey = (PGPPublicKey) keyIterator.next();
		if (pgpPublicKey.isEncryptionKey()) {
		    return pgpPublicKey;
		}
	    }
	}
	throw new IllegalArgumentException("Can't find encryption key in key ring.");

    }

    static PGPSecretKey readSecretKey(String secretKeyFile) throws IOException, PGPException {
	try (InputStream secretKeyFileInputStream = new BufferedInputStream(new FileInputStream(secretKeyFile));) {
	    PGPSecretKey secretKey = readSecretKey(secretKeyFileInputStream);
	    return secretKey;
	}
    }

    private static PGPSecretKey readSecretKey(InputStream secretKeyFileInputStream) throws IOException, PGPException {
	PGPSecretKeyRingCollection secretKeyRingCollection = new PGPSecretKeyRingCollection(
		PGPUtil.getDecoderStream(secretKeyFileInputStream), new JcaKeyFingerprintCalculator());
	// loop through the collection till we find a key suitable for
	// encryption
	Iterator<PGPSecretKeyRing> pgpKeyRingIterator = secretKeyRingCollection.getKeyRings();
	while (pgpKeyRingIterator.hasNext()) {
	    PGPSecretKeyRing pgpSecretKeyRing = (PGPSecretKeyRing) pgpKeyRingIterator.next();
	    Iterator<PGPSecretKey> secretKeyIterator = pgpSecretKeyRing.getSecretKeys();
	    while (secretKeyIterator.hasNext()) {
		PGPSecretKey pgpSecretKey = (PGPSecretKey) secretKeyIterator.next();
		if (pgpSecretKey.isSigningKey())
		    return pgpSecretKey;
	    }
	}

	throw new IllegalArgumentException("Can't find signing key in key ring.");

    }

}
