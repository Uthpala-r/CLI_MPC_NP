//! # Network Command-Line Interface (CLI) Application
//!
//! This file serves as the main module that initializes and links all other sub-modules.
//! The CLI provides a hierarchical command structure similar to Cisco's networking devices.


/// Modules included in the CLI application
mod cliconfig;
mod commandcompleter;
mod clicommands;
mod clock_settings;
mod run_config;
mod execute;
mod network_config;
mod show_c;
mod passwd;


/// Internal imports from the application's modules
use cliconfig::CliConfig;
use crate::cliconfig::CliContext;
use commandcompleter::CommandCompleter;
use clicommands::build_command_registry;
use execute::execute_command;
use clock_settings::Clock;
use crate::execute::Mode;


/// External crates for the CLI application
use rustyline::error::ReadlineError;
use rustyline::Editor;
use rustyline::history::DefaultHistory;
use std::collections::{HashSet, HashMap};
use ctrlc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use signal_hook::{consts::SIGTSTP, iterator::Signals};
use std::fs;
use std::path::Path;
use std::thread;

/// Main function of the CLI application.
///
/// This function initializes the Command-Line Interface (CLI) environment, processes user input,
/// and manages the interaction loop. The CLI supports commands for various configurations and
/// operations, with features such as command completion, history, and real-time mode switching.
///
/// # Functionality
/// - Builds a registry of commands and retrieves their names for command completion.
/// - Configures the CLI context, including hostname, modes, and other configurations.
/// - Sets up a Rustyline editor for user input with custom history and completion behavior.
/// - Configures signal handling for `Ctrl+C` and `Ctrl+Z`, emulating Cisco router behavior:
///   - In configuration modes, returns to Privileged mode
///   - In User mode, does nothing special
/// - Processes user input in a loop, executing commands, handling history, and responding to errors.
///
/// # Key Components
/// - **Command Registry**: A collection of available CLI commands, dynamically used for completion.
/// - **CLI Context**: Contains the current CLI state, including modes, selected interfaces, and VLANs.
/// - **Rustyline Editor**: Provides user input handling with features like auto-completion and history.
/// - **Clock Settings**: Maintains an optional system clock for configuration purposes.
/// - **Signal Handling**: Manages `Ctrl+C` and `Ctrl+Z` signals to emulate Cisco router behavior.
///
/// # Example Usage
/// ```bash
/// > Network> enable
/// > Network# configure terminal
/// > Network(config)# [Ctrl+C pressed]
/// > Network# exit cli
/// Exiting CLI...
/// ```
///
/// # Signals
/// - `Ctrl+C`: In configuration modes, returns to Privileged mode. In User mode, does nothing.
/// - `Ctrl+Z`: In configuration modes, returns to Privileged mode. In User mode, does nothing.
///
/// # Errors
/// - Any error during initialization or user input handling (e.g., `ReadlineError`) is logged and
///   terminates the CLI gracefully.
///
/// # History
/// - Command history is stored in `history.txt` and is reloaded on subsequent runs.
fn main() {

    // Build the registry of commands and retrieve their names
    let commands = build_command_registry();
    let command_names: Vec<String> = commands.keys().cloned().map(String::from).collect();
    
    // Define the initial hostname as "Network"
    let _initial_hostname = "Network".to_string();
    
    // Define the context for the CLI
    let mut context = CliContext {
        current_mode: Mode::UserMode,
        config: CliConfig::default(),
        prompt: format!("{}>", CliConfig::default().hostname),
        selected_interface: None,
    };

    // Configure the Rustyline editor with history behavior
    let config = rustyline::Config::builder()
    .history_ignore_space(true) 
    .completion_type(rustyline::CompletionType::List)
    .build();

    // Initialize the command-line editor with a custom command completer
    let mut rl = Editor::<CommandCompleter, DefaultHistory>::with_config(config)
        .expect("Failed to initialize editor");

    let mut commands_map: HashMap<String, Vec<String>> = HashMap::new();
    for command in command_names {
        commands_map.insert(command.clone(), vec![command.clone()]);
    }
    let completer = CommandCompleter::new(commands_map, Mode::UserMode, context.clone());
    rl.set_helper(Some(completer));

    if Path::new("history.txt").exists() {
        rl.load_history("history.txt").ok();
    }

    // Set up the initial clock settings
    let mut clock = Some(Clock::new());
    
    // Flag to indicate when Ctrl+C or Ctrl+Z is pressed to return to Privileged mode
    let return_to_privileged = Arc::new(AtomicBool::new(false));
    let return_to_privileged_clone = Arc::clone(&return_to_privileged);

    // Share context state with signal handlers
    let ctx_mode = Arc::new(std::sync::Mutex::new(Mode::UserMode));
    let ctx_mode_for_ctrlc = Arc::clone(&ctx_mode);
    let ctx_mode_for_ctrlz = Arc::clone(&ctx_mode);

    // Setup Ctrl+C handler with Cisco-like behavior
    ctrlc::set_handler(move || {
        let current_mode = ctx_mode_for_ctrlc.lock().unwrap();
        match *current_mode {
            Mode::UserMode => {
                // In User mode, do nothing special (like Cisco)
            },
            _ => {
                // In any other mode, set flag to return to Privileged mode
                return_to_privileged_clone.store(true, Ordering::SeqCst);
            }
        }
    }).expect("Error setting Ctrl+C handler");

    // Setup Ctrl+Z handler using signal-hook
    let return_to_privileged_clone_z = Arc::clone(&return_to_privileged);
    
    // Create a separate thread to handle SIGTSTP (Ctrl+Z)
    let mut signals = Signals::new(&[SIGTSTP]).expect("Error setting Ctrl+Z handler");
    thread::spawn(move || {
        for _ in signals.forever() {
            let current_mode = ctx_mode_for_ctrlz.lock().unwrap();
            match *current_mode {
                Mode::UserMode => {
                    // In User mode, do nothing special (like Cisco)
                },
                _ => {
                    // In any other mode, set flag to return to Privileged mode
                    return_to_privileged_clone_z.store(true, Ordering::SeqCst);
                }
            }
        }
    });

    // Main REPL loop for processing user input
    loop {
        // Check if we need to return to Privileged mode (from Ctrl+C or Ctrl+Z)
        if return_to_privileged.load(Ordering::SeqCst) {
            // Reset the flag
            return_to_privileged.store(false, Ordering::SeqCst);
            
            // Return to Privileged mode
            context.current_mode = Mode::PrivilegedMode;
            context.prompt = format!("{}#", context.config.hostname);
            // Reset interface selection when exiting config mode
            context.selected_interface = None;
            
            // Update the helper's mode
            if let Some(helper) = rl.helper_mut() {
                helper.current_mode = context.current_mode.clone();
            }
            
            // Update shared mode state
            *ctx_mode.lock().unwrap() = context.current_mode.clone();
            
            continue;
        }
        
        let prompt = context.prompt.clone();
        println!();
        match rl.readline(&prompt) {
            Ok(buffer) => {
                let input = buffer.trim();
                if input.is_empty() {
                    continue;
                }

                rl.add_history_entry(input);
                
                if input == "exit cli" {
                    println!("Exiting CLI...");
                    // Delete the history file
                    if let Err(_e) = fs::remove_file("history.txt") {
                        //println!("Warning: Could not delete history file: {}", e);
                    } else {
                        //println!("History file deleted.");
                    }
                    break;
                }

                rl.save_history("history.txt").ok();
            
                // Execute the command with the current context
                if let Some(helper) = rl.helper_mut() {
                    execute_command(input, &commands, &mut context, &mut clock, helper);
                    helper.current_mode = context.current_mode.clone();
                    
                    // Update shared mode state
                    *ctx_mode.lock().unwrap() = context.current_mode.clone();
                }
            }

            Err(ReadlineError::Interrupted) => {
                // This is redundant now as the Ctrl+C handler will set the return_to_privileged flag
                // but we keep it for robustness
                match context.current_mode {
                    Mode::UserMode => {
                        // In User mode, do nothing special (like Cisco)
                    },
                    _ => {
                        // In any other mode, return to Privileged mode
                        context.current_mode = Mode::PrivilegedMode;
                        context.prompt = format!("{}#", context.config.hostname);
                        context.selected_interface = None;
                        
                        if let Some(helper) = rl.helper_mut() {
                            helper.current_mode = context.current_mode.clone();
                        }
                        
                        // Update shared mode state
                        *ctx_mode.lock().unwrap() = context.current_mode.clone();
                    }
                }
            }

            Err(err) => {
                println!("Error: {:?}", err);
                break;
            }
        }
    }
}