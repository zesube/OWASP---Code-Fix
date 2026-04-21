import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

class PasswordVerifier {
    public boolean verifyPassword(String inputPassword, String storedValue)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        String[] parts = storedValue.split(":");
        int iterations = Integer.parseInt(parts[0]);
        byte[] salt = Base64.getDecoder().decode(parts[1]);
        byte[] expectedHash = Base64.getDecoder().decode(parts[2]);

        PBEKeySpec spec =
                new PBEKeySpec(inputPassword.toCharArray(), salt, iterations, expectedHash.length * 8);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] candidateHash = factory.generateSecret(spec).getEncoded();

        return MessageDigest.isEqual(candidateHash, expectedHash);
    }
}
