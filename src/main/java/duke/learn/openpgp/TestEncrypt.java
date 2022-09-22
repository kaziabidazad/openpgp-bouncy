/**
 * 
 */
package duke.learn.openpgp;

import java.io.IOException;

import org.bouncycastle.openpgp.PGPException;

/**
 * @author Kazi
 *
 */
public class TestEncrypt implements Util {

    public static void main(String[] args) throws IOException, PGPException {
	long startTime = System.currentTimeMillis();
	PGPLargeFileEncryptor.encrypt(ENCRYPTED_FILE_NAME, UNENCRYPTED_FILE_NAME, PUBLIC_KEY_NAME, false, false);
	long endTime = System.currentTimeMillis();
	long elapsedTime = endTime - startTime;
	System.out.println("Time taken to encrypt: " + (elapsedTime / 1000) + " s");

    }

}
