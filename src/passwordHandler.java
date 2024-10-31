import java.security.SecureRandom;

// Version 5.0 - Added passwordHandler class

public class passwordHandler {
    private static final SecureRandom random = new SecureRandom();
    private static final String characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    private static final int minPasswordLength = 8;
    public static final String alphaKey = "ARGOSROCK";
    public static final String numberKey = "1963";
    private static final String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

    // Version 3.0 - Resticting Password characters
    // Version 5.0 - Added exception handling
    public static boolean isValidPassword(String password) throws passwordPolicyException, passwordValidationException {
        if (password == null || password.length() < minPasswordLength) {
            throw new passwordPolicyException("Password must be at least " + minPasswordLength + " characters long.");
        }
        boolean hasUpper = false;
        boolean hasLower = false;
        boolean hasDigit = false;

        for (char c : password.toCharArray()) {
            if (Character.isUpperCase(c))
                hasUpper = true;
            if (Character.isLowerCase(c))
                hasLower = true;
            if (Character.isDigit(c))
                hasDigit = true;
        }
        if (!hasUpper || !hasLower || !hasDigit) {
            throw new passwordValidationException("Password must include:\n" +
                    "- At least 8 characters\n" +
                    "- At least one uppercase letter (A-Z)\n" +
                    "- At least one lowercase letter (a-z)\n" +
                    "- At least one digit (0-9)");
        }
        return true;
    }

    // Version 3.0 - Encryption for upper and lowercase letters

    public static String encryptVigenere(String key, String cleartext) {
        return vigenereCipher(key, cleartext, true);
    }

    // Version 3.0 - Decryption for upper and lowercase letters

    public static String decryptVigenere(String key, String ciphertext) {
        return vigenereCipher(key, ciphertext, false);
    }

    // Version 3.0 - Encryption for numeric values

    public static String encryptNumber(String numberKey, String cleartext) {
        return numericCipher(numberKey, cleartext, true);
    }

    // Version 3.0 - Decryption for numeric values

    public static String decryptNumber(String numberKey, String ciphertext) {
        return numericCipher(numberKey, ciphertext, false);
    }

    // Version - 3.0 Shared logic for alphabetic encryption
    private static String vigenereCipher(String key, String text, boolean isEncrypt) {
        StringBuilder resultText = new StringBuilder();
        int alphabetLength = alphabet.length();

        for (int i = 0; i < text.length(); i++) {
            char textChar = text.charAt(i);
            char keyChar = key.charAt(i % key.length());
            int textIndex = alphabet.indexOf(textChar);
            int keyIndex = alphabet.indexOf(keyChar);

            if (textIndex == -1) {
                resultText.append(textChar);
            } else {
                int resultIndex;

                if (isEncrypt) {
                    resultIndex = (textIndex + keyIndex) % alphabetLength; // Encryption
                } else {
                    resultIndex = (textIndex - keyIndex + alphabetLength) % alphabetLength; // Decryption
                }

                resultText.append(alphabet.charAt(resultIndex));
            }
        }
        return resultText.toString();
    }

    // Version 3.0 Shared logic for numeric encryption

    private static String numericCipher(String numberKey, String text, boolean isEncrypt) {
        StringBuilder resultText = new StringBuilder();
        int keyIndex = 0;

        for (int i = 0; i < text.length(); i++) {
            char textChar = text.charAt(i);

            if (Character.isDigit(textChar)) {
                int textNum = Character.getNumericValue(textChar);
                int keyNum = Character.getNumericValue(numberKey.charAt(keyIndex % numberKey.length()));

                int resultNum;
                if (isEncrypt) {
                    resultNum = (textNum + keyNum) % 10; // Encryption
                } else {
                    resultNum = (textNum - keyNum + 10) % 10; // Decryption
                }

                resultText.append(resultNum);
                keyIndex++;
            } else {
                resultText.append(textChar);
            }
        }

        return resultText.toString();
    }

    // Version 4.0 - Default password reqs
    public static String createDefaultPassword() throws defaultPasswordException {
        StringBuilder password = new StringBuilder();
        boolean hasUpper = false;
        boolean hasLower = false;
        boolean hasDigit = false;
    
        while (password.length() < minPasswordLength || !hasUpper || !hasLower || !hasDigit) {
            char c = characters.charAt(random.nextInt(characters.length()));
            password.append(c);
    
            if (Character.isUpperCase(c)) hasUpper = true;
            if (Character.isLowerCase(c)) hasLower = true;
            if (Character.isDigit(c)) hasDigit = true;
        }
    
        // Version 5.0 - Added exception handling
        try {
            if (!isValidPassword(password.toString())) {
                throw new defaultPasswordException("Failed to create a valid default password.");
            }
        } catch (passwordPolicyException | passwordValidationException e) {
            throw new defaultPasswordException("Failed to create a valid default password.");
        }

        return password.toString();
    }
    
    // Version 5.0 - Added exception handling
    public static class passwordPolicyException extends Exception {
        public passwordPolicyException(String message) {
            super(message);
        }
    }

    public static class passwordValidationException extends Exception {
        public passwordValidationException(String message) {
            super(message);
        }
    }

    public static class defaultPasswordException extends Exception {
        public defaultPasswordException(String message) {
            super(message);
        }
    }

}
