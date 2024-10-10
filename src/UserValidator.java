import java.util.regex.*;

public class UserValidator {

    // Minimum username length
    private static final int MIN_USERNAME_LENGTH = 6;
    
    // Method to validate the username and password
    public static void validateUser(String username, String password) throws IllegalArgumentException {
        // Check if the username is valid
        if (!isValidUsername(username)) {
            throw new IllegalArgumentException("Error: Username must be at least " + MIN_USERNAME_LENGTH + " characters long.");
        }

        // Check if the password is valid
        if (!isValidPassword(password)) {
            throw new IllegalArgumentException("Error: Password must contain at least one special character.");
        }

        // If both are valid
        System.out.println("User is successfully validated!");
    }

    // Method to validate the username
    private static boolean isValidUsername(String username) {
        // Check if the username meets the minimum length requirement
        return username != null && username.length() >= MIN_USERNAME_LENGTH;
    }

    // Method to validate the password (must contain at least one special character)
    private static boolean isValidPassword(String password) {
        if (password == null) return false;

        // Define a regular expression that looks for special characters
        String specialChars = ".*[!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>/?].*";
        Pattern pattern = Pattern.compile(specialChars);
        Matcher matcher = pattern.matcher(password);

        // Return true if the password contains at least one special character
        return matcher.find();
    }

    public static void main(String[] args) {
        // Test cases
        try {
            validateUser("user1", "Password123!"); // Valid case
        } catch (IllegalArgumentException e) {
            System.out.println(e.getMessage());
        }

        try {
            validateUser("user", "Password123!"); // Invalid username case
        } catch (IllegalArgumentException e) {
            System.out.println(e.getMessage());
        }

        try {
            validateUser("username", "Password123"); // Invalid password case
        } catch (IllegalArgumentException e) {
            System.out.println(e.getMessage());
        }
    }
}
