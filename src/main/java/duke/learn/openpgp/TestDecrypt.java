/**
 * 
 */
package duke.learn.openpgp;

import java.io.IOException;
import java.security.NoSuchProviderException;

/**
 * @author Kazi
 *
 */
public class TestDecrypt implements Util {

    public static void main(String[] args) throws NoSuchProviderException, IOException {
	long startTime = System.currentTimeMillis();
	PGPLargeFileDecryptor.decryptFile(ENCRYPTED_FILE_NAME, SECRET_KEY_NAME, PASSWORD.toCharArray(),
		DECRYPTED_FILE_NAME);
	long endTime = System.currentTimeMillis();
	long elapsedTime = endTime - startTime;
	System.out.println("Time taken to decrypt: " + (elapsedTime / 1000) + " s");

    }

}
