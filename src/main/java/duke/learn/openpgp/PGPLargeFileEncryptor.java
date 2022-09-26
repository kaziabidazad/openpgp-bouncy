/**
 * 
 */
package duke.learn.openpgp;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.security.Security;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;

/**
 * @author Kazi
 *
 */
public class PGPLargeFileEncryptor {

    private PGPLargeFileEncryptor() {
    }

    /**
     * 
     * @param outputFile
     * @param inputFile
     * @param encryptionKey
     * @param armor
     * @param withIntegrityCheck
     * @throws IOException
     * @throws PGPException
     */
    static void encrypt(String outputFile, String inputFile, String encryptionKey, boolean armor,
	    boolean withIntegrityCheck) throws IOException, PGPException {
	Security.addProvider(new BouncyCastleProvider());
	try (OutputStream outputStream = new BufferedOutputStream(new FileOutputStream(outputFile));) {
	    PGPPublicKey pgpPublicKey = OpenPGPUtil.readPublicKey(encryptionKey);
	    encrypt(outputStream, inputFile, pgpPublicKey, armor, withIntegrityCheck);
	}
    }

    /**
     * 
     * @param outputFileStream
     * @param inputFile
     * @param publicKey
     * @param armor
     * @param withIntegrityCheck
     * @throws IOException
     * @throws PGPException
     */
    private static void encrypt(OutputStream outputFileStream, String inputFile, PGPPublicKey publicKey, boolean armor,
	    boolean withIntegrityCheck) throws IOException, PGPException {
	if (armor)
	    outputFileStream = new ArmoredOutputStream(outputFileStream);
	try {
	    PGPEncryptedDataGenerator encryptedDataGenerator = new PGPEncryptedDataGenerator(
		    new JcePGPDataEncryptorBuilder(PGPEncryptedData.AES_256).setWithIntegrityPacket(withIntegrityCheck)
			    .setSecureRandom(new SecureRandom()).setProvider("BC"));

	    encryptedDataGenerator.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(publicKey).setProvider("BC"));

	    OutputStream outputStream = encryptedDataGenerator.open(outputFileStream, new byte[1 << 16]);

	    PGPCompressedDataGenerator compressedDataGenerator = new PGPCompressedDataGenerator(
		    PGPCompressedData.BZIP2);

	    // Write out the contents of the provided file as a literal data packet in
	    // partial packet format
	    PGPUtil.writeFileToLiteralData(compressedDataGenerator.open(outputStream), PGPLiteralData.BINARY,
		    new File(inputFile), new byte[1 << 16]);

	    compressedDataGenerator.close();
	    outputStream.close();
	    if (armor) {
		outputFileStream.close();
	    }
	} catch (PGPException e) {
	    System.err.println(e);
	    if (e.getUnderlyingException() != null) {
		e.getUnderlyingException().printStackTrace();
	    }
	}

    }
}
