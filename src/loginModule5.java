import java.io.Console;

public class loginModule5 {

    // Version 2.0 - Updated database to meet password requirements.
    // Version 3.0 - Added Vigenere cipher
    // Version 5.0 - Addded passwordHandler class
    static String[][] database = {
            { "scientist", passwordHandler.encryptVigenere(passwordHandler.alphaKey, "Drowssap1") },
            { "engineer", passwordHandler.encryptVigenere(passwordHandler.alphaKey, "Pathword2") },
            { "security", passwordHandler.encryptVigenere(passwordHandler.alphaKey, "NotSecure3") }
    };
    // Version 4.0 - CHanged login attempts to 2
    static final int MAX_LOGIN_ATTEMPTS = 2;
    static boolean isLocked = false;

    public static void main(String[] args) {
        Console console = System.console();
        // Check if the console is available
        if (console == null) {
            System.out.println("No console available");
            return;
        }
        System.out.println("Welcome to the Login System");
        // Version 4.0 - Registration, login, or quit
        while (true) {
            System.out.println("Would you like to [1] Register, [2] Login, or [3] Quit? ");
            String choice = console.readLine();

            if ("1".equals(choice)) {
                registerUser(console);
            } else if ("2".equals(choice)) {
                loginUser(console);
            } else if ("3".equals(choice)) {
                System.out.println("Exiting the application. Goodbye!");
                break;
            } else {
                System.out.println("Invalid choice. Please enter 1 for Register, 2 for Login, or 3 to Quit.");
            }
        }
    }

    // Version 4.0 - Register new users
    private static void registerUser(Console console) {
        System.out.println("User Registration");

        String newUsername = console.readLine("Enter a new username: ");
        // Version 4.0 - Makes sure username isnt already in use
        for (String[] user : database) {
            if (user[0].equals(newUsername)) {
                System.out.println("Username is already taken. Please try a different one.");
                return;
            }
        }

        int passwordAttempts = 0;
        String newPassword = null;

        while (passwordAttempts < 3) {
            char[] passwordArray = console.readPassword("Create a new password: ");
            newPassword = new String(passwordArray);

            // Version 5.0 Exception handling
            try {
                if (passwordHandler.isValidPassword(newPassword)) {
                    String encryptedPassword = passwordHandler.encryptVigenere(passwordHandler.alphaKey, newPassword);
                    addUserToDatabase(newUsername, encryptedPassword);
                    System.out.println("User registered successfully with your entered password!");
                    return;
                } else {
                    passwordAttempts++;
                    System.out.println("Invalid password. Make sure it follows the password policy:\n" + getPasswordPolicy());
                }
            } catch (passwordHandler.passwordPolicyException | passwordHandler.passwordValidationException e) {
                passwordAttempts++;
                System.out.println("Password validation failed: " + e.getMessage());
            }
        }
        // Version 4.0 - assigns default password after 2 failed attempts
        if (passwordAttempts == 3) {

            // Version 5.0 Exception handling
            try {
                newPassword = passwordHandler.createDefaultPassword();
                String encryptedPassword = passwordHandler.encryptVigenere(passwordHandler.alphaKey, newPassword);
                addUserToDatabase(newUsername, encryptedPassword);
                System.out.println("A default password will be provided to you through email.");
                System.out.println("Email: " + newPassword);
                System.out.println("User registered successfully with a default password!");
            } catch (passwordHandler.defaultPasswordException e) {
                System.out.println("Failed to create a default password: " + e.getMessage());
            }
        }
    }

    // Version 4.0 - Add new user to the database
    private static void addUserToDatabase(String username, String encryptedPassword) {
        String[][] newDatabase = new String[database.length + 1][2];
        for (int i = 0; i < database.length; i++) {
            newDatabase[i] = database[i];
        }
        newDatabase[database.length] = new String[] { username, encryptedPassword };
        database = newDatabase;
    }

    private static void loginUser(Console console) {
        int attempts = 0;

        while (!isLocked) {
            // Enter Username
            String username = console.readLine("Enter your username: ");

            // Source: GeeksforGeeks, "Console readPassword() method in Java with examples"
            // URL:
            // https://www.geeksforgeeks.org/console-readpassword-method-in-java-with-examples/
            // Accessed on: 8/28/2024

            // Enter password (characters hidden)
            char[] passwordArray = console.readPassword("Enter your password: ");
            String password = new String(passwordArray);

            // Increment login attempts and check if limit is reached
            attempts++;
            checkAttempts(attempts);

            if (isLocked)
                break;

            // Validate username and password inputs
            if (!isValidInput(username)) {
                System.out.println("Invalid username: Only alphanumeric characters are allowed.");
                continue;
            }
            
            try {
                if (!passwordHandler.isValidPassword(password)) {
                    System.out.println(
                            "Invalid password. Please make sure it follows the password policy: \n" + getPasswordPolicy());
                    continue;
                }
            } catch (passwordHandler.passwordPolicyException | passwordHandler.passwordValidationException e) {
                System.out.println("Password validation failed: " + e.getMessage());
                continue;
            }
            // Version 3.0 - Encryption
            String encryptedPassword = passwordHandler.encryptVigenere(passwordHandler.alphaKey, password);

            // Authenticate the user and display original/encrypted/decrypted values
            if (authenticate(username, encryptedPassword, password)) {
                System.out.println("Login successful!");
                attempts = 0;
                break;
            } else {
                System.out.println("Invalid credentials. Please try again.");
            }
        }
        // Version 3.0 - Different account lock message
        if (isLocked) {
            System.out.println("Too many failed attempts. Please try again later.");
            System.out.println("The account is locked due to too many failed login attempts.");
        }
    }

    // Version 3.0 - Different account lock
    private static void checkAttempts(int attempts) {
        if (attempts >= MAX_LOGIN_ATTEMPTS) {
            isLocked = true;
        }
    }

    // Version 3.0 - Adjusted the login feedback showing the encrypted password
    private static boolean authenticate(String username, String encryptedPassword, String originalPassword) {
        for (String[] user : database) {
            if (user[0].equals(username) && user[1].equals(encryptedPassword)) {
                // Encrypt the username using Vigenere cipher
                String encryptedUsername = passwordHandler.encryptVigenere(passwordHandler.alphaKey, username);

                // Decrypt both username and password to display after successful login
                String decryptedUsername = passwordHandler.decryptVigenere(passwordHandler.alphaKey,
                        encryptedUsername);
                String decryptedPassword = passwordHandler.decryptVigenere(passwordHandler.alphaKey,
                        encryptedPassword);

                System.out.println("--------- Welcome --------");
                System.out.println("Original Username: " + username);
                System.out.println("Encrypted Username: " + encryptedUsername);
                System.out.println("Decrypted Username: " + decryptedUsername);
                System.out.println();
                System.out.println("Original Password: " + originalPassword);
                System.out.println("Encrypted Password: " + encryptedPassword);
                System.out.println("Decrypted Password: " + decryptedPassword);
                System.out.println("--------------------------");

                return true;
            }
        }
        return false;
    }

    // Version 3.0 - Resticting login characters
    private static boolean isValidInput(String input) {
        return input != null && input.matches("[a-zA-Z0-9]+");
    }

    // Version 4.0 - Returns the password policy
    private static String getPasswordPolicy() {
        return "Password must include:\n" +
                "- At least 8 characters\n" +
                "- At least one uppercase letter (A-Z)\n" +
                "- At least one lowercase letter (a-z)\n" +
                "- At least one digit (0-9)";
    }
}
