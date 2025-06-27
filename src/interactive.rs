//! # Interactive User Input Module
//!
//! This module provides a collection of user-friendly interactive prompts for
//! gathering input during cryptographic operations. It uses the `dialoguer` crate
//! to create polished command-line interfaces with validation and error handling.
//!
//! ## Features
//!
//! - **Text Input**: Standard text prompts with validation
//! - **Password Input**: Secure password entry with hidden input
//! - **Numeric Input**: Number prompts with range validation
//! - **Choice Selection**: Multiple choice menus with keyboard navigation
//!
//! ## Error Handling
//!
//! All functions return `Result<T>` to enable proper error propagation and
//! user-friendly error messages when input operations fail.

use anyhow::{Context, Result};
use dialoguer::{Input, Password, Select};

/// Prompt user for text input with validation
///
/// Displays a formatted prompt and waits for user input. The function handles
/// basic input validation and provides context for error messages.
///
/// # Arguments
///
/// * `prompt` - The message to display to the user
///
/// # Returns
///
/// Returns the user's input as a `String` wrapped in a `Result`.
///
/// # Examples
///
/// ```rust
/// use ruscrypt::interactive;
///
/// let text = interactive::prompt_for_input("Enter your message")?;
/// println!("You entered: {}", text);
/// ```
///
/// # Errors
///
/// Returns an error if:
/// - The input stream is interrupted (Ctrl+C)
/// - Terminal I/O fails
/// - The prompt cannot be displayed
pub fn prompt_for_input(prompt: &str) -> Result<String> {
    let input = Input::<String>::new()
        .with_prompt(prompt)
        .interact()
        .context("Failed to read user input")?;

    Ok(input)
}

/// Prompt user for password input with hidden characters
///
/// Displays a password prompt where user input is not echoed to the terminal
/// for security. This is ideal for sensitive information like encryption keys
/// and passwords.
///
/// # Arguments
///
/// * `prompt` - The message to display to the user
///
/// # Returns
///
/// Returns the user's password as a `String` wrapped in a `Result`.
///
/// # Security Features
///
/// - Input is not displayed on screen
/// - Password is not logged or stored in command history
/// - Memory is cleared after use (handled by dialoguer)
///
/// # Examples
///
/// ```rust
/// use ruscrypt::interactive;
///
/// let key = interactive::prompt_for_password("Enter encryption key")?;
/// // Use key for cryptographic operations
/// ```
///
/// # Errors
///
/// Returns an error if:
/// - The input stream is interrupted
/// - Terminal I/O fails
/// - The password prompt cannot be displayed
pub fn prompt_for_password(prompt: &str) -> Result<String> {
    let password = Password::new().with_prompt(prompt).interact().context(
        "Failed to read password",
    )?;

    Ok(password)
}

/// Prompt user for numeric input with range validation
///
/// Displays a numeric prompt and validates that the input falls within the
/// specified range. The function will continue prompting until valid input
/// is provided or the user cancels.
///
/// # Arguments
///
/// * `prompt` - The message to display to the user
/// * `min` - Minimum allowed value (inclusive)
/// * `max` - Maximum allowed value (inclusive)
///
/// # Returns
///
/// Returns the user's numeric input as a `u32` wrapped in a `Result`.
///
/// # Validation
///
/// The function automatically validates that:
/// - Input is a valid number
/// - Number is within the specified range [min, max]
/// - Provides helpful error messages for invalid input
///
/// # Examples
///
/// ```rust
/// use ruscrypt::interactive;
///
/// // Prompt for a shift value between 1 and 25
/// let shift = interactive::prompt_for_number("Enter shift value", 1, 25)?;
/// println!("Shift: {}", shift);
/// ```
///
/// # Errors
///
/// Returns an error if:
/// - The input stream is interrupted
/// - Terminal I/O fails
/// - The prompt cannot be displayed
/// - User provides non-numeric input repeatedly
pub fn prompt_for_number(prompt: &str, min: u32, max: u32) -> Result<u32> {
    let number = Input::<u32>::new()
        .with_prompt(prompt)
        .validate_with(move |input: &u32| -> Result<(), String> {
            if *input >= min && *input <= max {
                Ok(())
            } else {
                Err(format!("Please enter a number between {} and {}", min, max))
            }
        })
        .interact()
        .context("Failed to read number")?;

    Ok(number)
}

/// Prompt user to select from a list of choices
///
/// Displays an interactive menu where users can navigate with arrow keys
/// and select an option with Enter. This provides a user-friendly alternative
/// to typing exact strings.
///
/// # Arguments
///
/// * `prompt` - The message to display above the choice list
/// * `choices` - Array of string slices representing the available options
///
/// # Returns
///
/// Returns the selected choice as a `String` wrapped in a `Result`.
///
/// # User Interface
///
/// - Arrow keys (↑/↓) navigate the list
/// - Enter key selects the highlighted option
/// - First option is selected by default
/// - Options are displayed with visual highlighting
///
/// # Examples
///
/// ```rust
/// use ruscrypt::interactive;
///
/// let encoding = interactive::prompt_for_choices(
///     "Select output encoding",
///     &["base64", "hex", "binary"]
/// )?;
/// println!("Selected: {}", encoding);
/// ```
///
/// # Errors
///
/// Returns an error if:
/// - The input stream is interrupted
/// - Terminal I/O fails
/// - The menu cannot be displayed
/// - No choices are provided (empty array)
pub fn prompt_for_choices(prompt: &str, choices: &[&str]) -> Result<String> {
    let selection = Select::new()
        .with_prompt(prompt)
        .items(choices)
        .default(0)
        .interact()
        .context("Failed to select an option")?;

    Ok(choices[selection].to_string())
}
