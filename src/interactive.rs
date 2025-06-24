use anyhow::{Context, Result};
use dialoguer::{Input, Password, Select};

pub fn prompt_for_input(prompt: &str) -> Result<String> {
    let input = Input::<String>::new()
        .with_prompt(prompt)
        .interact()
        .context("Failed to read user input")?;

    Ok(input)
}

pub fn prompt_for_password(prompt: &str) -> Result<String> {
    let password = Password::new().with_prompt(prompt).interact().context(
        "Failed to read password",
    )?;

    Ok(password)
}

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

pub fn prompt_for_choices(prompt: &str, choices: &[&str]) -> Result<String> {
    let selection = Select::new()
        .with_prompt(prompt)
        .items(choices)
        .default(0)
        .interact()
        .context("Failed to select an option")?;

    Ok(choices[selection].to_string())
}
