/**
 * 
 */
package duke.learn.openpgp;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Iterator;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.util.io.Streams;

/**
 * @author Kazi
 *
 */
public class PGPLargeFileDecryptor {

    private PGPLargeFileDecryptor() {

    }

    /**
     * 
     * @param encryptedFile
     * @param secretkeyFileName
     * @param password
     * @param outputFileName
     * @throws IOException
     * @throws NoSuchProviderException
     */
    static void decryptFile(String encryptedFile, String secretkeyFileName, char[] password, String outputFileName)
	    throws IOException, NoSuchProviderException {
	Security.addProvider(new BouncyCastleProvider());
	try (InputStream encryptedFileInStream = new BufferedInputStream(new FileInputStream(encryptedFile));
		InputStream secretkeyInStream = new BufferedInputStream(new FileInputStream(secretkeyFileName));) {
	    decryptFile(encryptedFileInStream, secretkeyInStream, password, outputFileName);
	}
    }

    /**
     * 
     * @param encryptedFileInStream
     * @param secretkeyInStream
     * @param password
     * @param outputFileName
     * @throws IOException
     * @throws NoSuchProviderException
     */
    private static void decryptFile(InputStream encryptedFileInStream, InputStream secretkeyInStream, char[] password,
	    String outputFileName) throws IOException, NoSuchProviderException {
	encryptedFileInStream = PGPUtil.getDecoderStream(encryptedFileInStream);

	try {
	    JcaPGPObjectFactory pgpObjectFactory = new JcaPGPObjectFactory(encryptedFileInStream);
	    PGPEncryptedDataList encryptedDataList;

	    Object o = pgpObjectFactory.nextObject();
	    //
	    // the first object might be a PGP marker packet.
	    //
	    if (o instanceof PGPEncryptedDataList) {
		encryptedDataList = (PGPEncryptedDataList) o;
	    } else {
		encryptedDataList = (PGPEncryptedDataList) pgpObjectFactory.nextObject();
	    }

	    //
	    // find the secret key
	    //
	    Iterator<PGPEncryptedData> encryptedDataIterator = encryptedDataList.getEncryptedDataObjects();
	    PGPPrivateKey secretKey = null;
	    PGPPublicKeyEncryptedData publicKeyEncryptedData = null;
	    PGPSecretKeyRingCollection secretKeyRingCollection = new PGPSecretKeyRingCollection(
		    PGPUtil.getDecoderStream(secretkeyInStream), new JcaKeyFingerprintCalculator());

	    while (secretKey == null && encryptedDataIterator.hasNext()) {
		publicKeyEncryptedData = (PGPPublicKeyEncryptedData) encryptedDataIterator.next();

		secretKey = OpenPGPUtil.findSecretKey(secretKeyRingCollection, publicKeyEncryptedData.getKeyID(), password);
	    }

	    if (secretKey == null) {
		throw new IllegalArgumentException("secret key for message not found.");
	    }

	    InputStream clear = publicKeyEncryptedData
		    .getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(secretKey));

	    JcaPGPObjectFactory plainFact = new JcaPGPObjectFactory(clear);

	    PGPCompressedData ccompressedData = (PGPCompressedData) plainFact.nextObject();

	    InputStream compressedStream = new BufferedInputStream(ccompressedData.getDataStream());
	    JcaPGPObjectFactory jcaPGPObjectFactory = new JcaPGPObjectFactory(compressedStream);

	    Object message = jcaPGPObjectFactory.nextObject();

	    if (message instanceof PGPLiteralData) {
		PGPLiteralData literalData = (PGPLiteralData) message;

//		String outFileName = literalData.getFileName();
//		if (outFileName.length() == 0) {
//		    outFileName = outputFileName;
//		}

		InputStream unc = literalData.getInputStream();
		OutputStream fOut = new FileOutputStream(outputFileName);

		Streams.pipeAll(unc, fOut, 8192);

		fOut.close();
	    } else if (message instanceof PGPOnePassSignatureList) {
		throw new PGPException("encrypted message contains a signed message - not literal data.");
	    } else {
		throw new PGPException("message is not a simple encrypted file - type unknown.");
	    }

	    if (publicKeyEncryptedData.isIntegrityProtected()) {
		if (!publicKeyEncryptedData.verify()) {
		    System.err.println("message failed integrity check");
		} else {
		    System.err.println("message integrity check passed");
		}
	    } else {
		System.err.println("no message integrity check");
	    }
	} catch (PGPException e) {
	    System.err.println(e);
	    if (e.getUnderlyingException() != null) {
		e.getUnderlyingException().printStackTrace();
	    }
	}
    }
}
