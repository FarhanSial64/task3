import java.util.HashMap;
import java.util.Map;
import java.util.regex.*;

public class UserValidator {

    // Mock user database (maps username to email)
    private static Map<String, String> userDatabase = new HashMap<>();

    // Minimum username length
    private static final int MIN_USERNAME_LENGTH = 6;

    // Method to validate the username, password, and email, then register the user
    public static void validateUser(String username, String password, String email) throws IllegalArgumentException {
        // Check if username is already registered
        if (userDatabase.containsKey(username)) {
            log("Registration failed: Username '" + username + "' is already taken.");
            throw new IllegalArgumentException("Error: Username is already taken.");
        }

        // Check if the username is valid
        if (!isValidUsername(username)) {
            throw new IllegalArgumentException("Error: Username must be at least " + MIN_USERNAME_LENGTH + " characters long.");
        }

        // Check if the password is valid
        if (!isValidPassword(password)) {
            throw new IllegalArgumentException("Error: Password must contain at least one special character.");
        }

        // Check if the email is valid
        if (!isValidEmail(email)) {
            throw new IllegalArgumentException("Error: Email is not valid.");
        }

        // If all validations pass, register the user
        userDatabase.put(username, email);
        log("Registration successful: User '" + username + "' has been registered.");
        System.out.println("User is successfully validated and registered!");
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

    // Method to validate email format
    private static boolean isValidEmail(String email) {
        if (email == null) return false;

        // Simple regex to validate email
        String emailRegex = "^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+$";
        Pattern pattern = Pattern.compile(emailRegex);
        Matcher matcher = pattern.matcher(email);

        return matcher.matches();
    }

    // Method to log user actions (for simplicity, logs to console)
    private static void log(String message) {
        System.out.println("[LOG]: " + message);
    }

    public static void main(String[] args) {
        // Test cases
        try {
            validateUser("user1", "Password123!", "user1@example.com"); // Valid case
        } catch (IllegalArgumentException e) {
            System.out.println(e.getMessage());
        }

        try {
            validateUser("user1", "Password123!", "user1@example.com"); // Duplicate username case
        } catch (IllegalArgumentException e) {
            System.out.println(e.getMessage());
        }

        try {
            validateUser("user", "Password123!", "user2@example.com"); // Invalid username case
        } catch (IllegalArgumentException e) {
            System.out.println(e.getMessage());
        }

        try {
            validateUser("username", "Password123", "user3@example.com"); // Invalid password case
        } catch (IllegalArgumentException e) {
            System.out.println(e.getMessage());
        }

        try {
            validateUser("username2", "Password@123", "invalidEmail"); // Invalid email case
        } catch (IllegalArgumentException e) {
            System.out.println(e.getMessage());
        }
    }
}
