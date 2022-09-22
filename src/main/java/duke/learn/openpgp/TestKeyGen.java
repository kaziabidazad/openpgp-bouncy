/**
 * 
 */
package duke.learn.openpgp;

import java.io.File;
import java.io.IOException;

/**
 * @author Kazi
 *
 */
public class TestKeyGen implements Util {

    /**
     * @param args
     */
    public static void main(String[] args) {
	File secretFile = new File(PUBLIC_KEY_NAME);
	File publicFile = new File(SECRET_KEY_NAME);
	try {
	    secretFile.getParentFile().mkdirs();
	    publicFile.getParentFile().mkdirs();
	    secretFile.createNewFile();
	    publicFile.createNewFile();
	    RSAKeyPairGenerator.generateKeyPair(publicFile.getAbsolutePath(), secretFile.getAbsolutePath(),
		   IDENTITY, PASSWORD);
	} catch (IOException e) {
	    // TODO Auto-generated catch block
	    e.printStackTrace();
	}

    }

}
