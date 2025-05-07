/// External crates for the CLI application
use crate::build_command_registry;
use crate::execute::Mode;
use crate::execute::Command;
use crate::CliContext;

use rustyline::hint::Hinter;
use rustyline::Helper;
use rustyline::completion::{Completer, Pair};
use rustyline::highlight::Highlighter;
use rustyline::validate::{Validator, ValidationContext, ValidationResult};
use rustyline::error::ReadlineError;
use std::collections::HashMap;


/// A custom completer for the CLI application.
///
/// The `CommandCompleter` provides suggestions for commands based on user input.
/// It integrates with the `rustyline` crate to offer real-time command-line assistance.
///
/// # Fields
/// - `commands`: A vector of strings containing the list of available commands.
/// - `current_mode`: Gets the current mode of the cli
/// 
#[derive(Clone)]
pub struct CommandCompleter {
    pub commands: HashMap<String, Vec<String>>,
    pub current_mode: Mode,
    pub context: CliContext,
}

/// Implementation of the `CommandCompleter` struct.
///
/// Provides a constructor for creating a new `CommandCompleter` instance, which is responsible
/// for handling command completion based on the available commands and the current CLI mode.
impl CommandCompleter {
    /// Creates a new `CommandCompleter` instance.
    ///
    /// # Arguments
    /// - `commands`: A `HashMap` where the keys are command names (as `String`) and the values are
    ///   vectors of possible completions or subcommands associated with each command.
    /// - `current_mode`: The current CLI mode (`Mode`), which influences the available commands
    ///   and their completion behavior.
    ///
    /// # Returns
    /// A new instance of `CommandCompleter` initialized with the provided commands and current mode.
    ///
    /// # Example
    /// ```rust
    /// use std::collections::HashMap;
    /// 
    /// let mut commands = HashMap::new();
    /// commands.insert("show".to_string(), vec!["ip".to_string(), "version".to_string()]);
    /// commands.insert("configure".to_string(), vec!["terminal".to_string()]);
    /// 
    /// let completer = CommandCompleter::new(commands, Mode::UserMode);
    /// ```
    pub fn new(commands: HashMap<String, Vec<String>>, current_mode: Mode, context: CliContext) -> Self {
        CommandCompleter {
            commands,
            current_mode,
            context,
        }
    }

}


/// Implements the `Completer` trait for the `CommandCompleter` struct.
impl Completer for CommandCompleter {
    type Candidate = Pair;

    /// Generates a list of command suggestions based on the current user input.
    ///
    /// # Arguments
    /// - `line`: The current input line from the user.
    /// - `pos`: The cursor position within the line.
    /// - `_ctx`: The rustyline context.
    ///
    /// # Returns
    /// A tuple where:
    /// - The first element is the starting position of the match in the input line.
    /// - The second element is a vector of `Pair` objects representing the suggestions.
    ///
    /// # Errors
    /// Returns a `ReadlineError` if an error occurs during completion.
    fn complete(
        &self,
        line: &str,
        pos: usize,
        _ctx: &rustyline::Context<'_>,
    ) -> Result<(usize, Vec<Self::Candidate>), rustyline::error::ReadlineError> {
        let suggestions = build_command_registry();
        let mut candidates = Vec::new();
        //let mut context = self.context.borrow_mut();

        let query = if pos <= line.len() {
            &line[..pos]
        } else {
            line
        };

        let parts: Vec<&str> = query.trim_end().split_whitespace().collect();

        // Filter commands allowed in the current mode
        let allowed_commands: Vec<(&str, &Command)> = suggestions
            .iter()
            .filter(|(&command, _)| is_command_allowed_in_mode(&command.to_string(), &self.current_mode))
            .map(|(command, cmd)| (*command, cmd))
            .collect();

        if parts.is_empty() {
            // No input yet: Show all allowed commands
            for (command_name, _) in allowed_commands.iter() {
                candidates.push(Pair {
                    display: command_name.to_string(),
                    replacement: command_name.to_string(),
                });
            }
        } 
        else if parts.len() == 1 && !query.ends_with(' ') {
            // First tab: Suggest commands matching the input
            for (command_name, _) in allowed_commands.iter() {
                if command_name.starts_with(parts[0]) {
                    candidates.push(Pair {
                        display: command_name.to_string(),
                        replacement: command_name.to_string(),
                    });
                }
            }
        } else if parts.len() >= 1 {
            if is_command_allowed_in_mode(&parts[0].to_string(), &self.current_mode) {
        
                if parts.len() == 1 && query.ends_with(' ') {
                    // Suggest subcommands for the main command
                    if let Some(subcommands) = suggestions.get(parts[0]) {
                        for subcmd in subcommands.suggestions.iter() {
                            candidates.push(Pair {
                                display: subcmd.join(" "),
                                replacement: format!("{} {}", parts[0], subcmd.join(" ")),
                            });
                        }
                    }
                }
                else if parts.len() == 2 && !query.ends_with(' ') {
                    // Suggest specific subcommands that start with the entered prefix
                    if let Some(command) = suggestions.get(parts[0]) {
                        if let Some(subcommands) = &command.suggestions {
                            for &subcmd in subcommands {
                                if subcmd.starts_with(parts[1]) {
                                    candidates.push(Pair {
                                        display: subcmd.to_string(),
                                        replacement: subcmd.to_string(),
                                    });
                                }
                            }
                        }
                    }
                } else if parts.len() == 2 && query.ends_with(' ') {
                    // Suggest third word based on suggestions2 when space is after second word
                    if let Some(command) = suggestions.get(parts[0]) {
                        if let Some(subcommands) = &command.suggestions2 {
                            for &subcmd in subcommands {
                                candidates.push(Pair {
                                    display: subcmd.to_string(),
                                    replacement: format!("{} {} {}", parts[0], parts[1], subcmd),
                                });
                            }
                        }
                    }
                } else if parts.len() == 3 && !query.ends_with(' ') {
                    // Suggest completions for partial third word
                    if parts[0] == "do" && parts[1] == "clock" && parts[2].starts_with("s") {
                        let show_options = vec!["set"];
                        for option in show_options {
                            candidates.push(Pair {
                                display: format!("{}", option),
                                replacement: format!("{}", option),
                            });
                        
                        }
                    } else if parts[0] == "do" && parts[1] == "debug" && parts[2].starts_with("a") {
                        let show_options = vec!["all"];
                        for option in show_options {
                            candidates.push(Pair {
                                display: format!("{}", option),
                                replacement: format!("{}", option),
                            });
                        
                        }
                    } else if parts[0] == "do" && parts[1] == "undebug" && parts[2].starts_with("a") {
                        let show_options = vec!["all"];
                        for option in show_options {
                            candidates.push(Pair {
                                display: format!("{}", option),
                                replacement: format!("{}", option),
                            });
                        
                        }
                    } else if parts[0] == "interface" && parts[2].starts_with("m") {
                        let show_options = vec!["mode"];
                        for option in show_options {
                            candidates.push(Pair {
                                display: format!("{}", option),
                                replacement: format!("{}", option),
                            });
                        
                        }
                    } else if parts[0] == "enable" && parts[2].starts_with("i") {
                        let show_options = vec!["id"];
                        for option in show_options {
                            candidates.push(Pair {
                                display: format!("{}", option),
                                replacement: format!("{}", option),
                            });
                        
                        }
                    }
                    
                    else if parts[0] == "network" {
                        if parts[2].starts_with("i") {
                            let show_options = vec!["ip"];
                            for option in show_options {
                                candidates.push(Pair {
                                    display: format!("{}", option),
                                    replacement: format!("{}", option),
                                });
                            
                            }
                        }
                        else if parts[2].starts_with("n") {
                            let show_options = vec!["netmask"];
                            for option in show_options {
                                candidates.push(Pair {
                                    display: format!("{}", option),
                                    replacement: format!("{}", option),
                                });
                            
                            }
                        }
                        
                        if parts[2].starts_with("a") {
                            let show_options = vec!["area"];
                            for option in show_options {
                                candidates.push(Pair {
                                    display: format!("{}", option),
                                    replacement: format!("{}", option),
                                });
                            
                            }
                        }
                    }
                    else if let Some(command) = suggestions.get(parts[0]) {
                        if let Some(subcommands) = &command.suggestions2 {
                            for &subcmd in subcommands {
                                if subcmd.starts_with(parts[2]) {
                                    candidates.push(Pair {
                                        display: subcmd.to_string(),
                                        replacement: subcmd.to_string(),
                                    });
                                }
                            }
                        }
                    } 
                } else if parts.len() == 4 && parts[0] == "show" {
                    // Add show subcommands for UserMode as suggestions
                    let show_options = vec!["brief"];
                    for option in show_options {
                        candidates.push(Pair {
                            display: format!("{}", option),
                            replacement: format!("{}", option),
                        });
                    
                    }
                }
                else if parts.len() == 4 && parts[0] == "priority" {
                    // Add show subcommands for UserMode as suggestions
                    let show_options = vec!["interface"];
                    for option in show_options {
                        candidates.push(Pair {
                            display: format!("{}", option),
                            replacement: format!("{}", option),
                        });
                    
                    }
                }
                else if parts.len() == 4 && parts[0] == "add" && parts[3].starts_with("i"){
                    // Add show subcommands for UserMode as suggestions
                    let show_options = vec!["interface"];
                    for option in show_options {
                        candidates.push(Pair {
                            display: format!("{}", option),
                            replacement: format!("{}", option),
                        });
                    
                    }
                }
                else if parts.len() == 4 && parts[0] == "add" && parts[3].starts_with("p"){
                    // Add show subcommands for UserMode as suggestions
                    let show_options = vec!["protocol"];
                    for option in show_options {
                        candidates.push(Pair {
                            display: format!("{}", option),
                            replacement: format!("{}", option),
                        });
                    
                    }
                }
                else if parts.len() == 4 && parts[0] == "do" && parts[3].starts_with("i"){
                    // Add show subcommands for UserMode as suggestions
                    let show_options = vec!["interface"];
                    for option in show_options {
                        candidates.push(Pair {
                            display: format!("{}", option),
                            replacement: format!("{}", option),
                        });
                    
                    }
                } else if parts.len() == 4 && parts[0] == "do" && parts[3].starts_with("r"){
                    // Add show subcommands for UserMode as suggestions
                    let show_options = vec!["route"];
                    for option in show_options {
                        candidates.push(Pair {
                            display: format!("{}", option),
                            replacement: format!("{}", option),
                        });
                    
                    }
                } else if parts.len() == 4 && parts[0] == "do" && parts[3].starts_with("a"){
                    // Add show subcommands for UserMode as suggestions
                    let show_options = vec!["associations"];
                    for option in show_options {
                        candidates.push(Pair {
                            display: format!("{}", option),
                            replacement: format!("{}", option),
                        });
                    
                    }
                } else if parts.len() == 4 && parts[0] == "do" && parts[3].starts_with("s"){
                    // Add show subcommands for UserMode as suggestions
                    let show_options = vec!["startup-config"];
                    for option in show_options {
                        candidates.push(Pair {
                            display: format!("{}", option),
                            replacement: format!("{}", option),
                        });
                    
                    }
                }
                else if parts.len() == 4 && parts[0] == "enable" && parts[3].starts_with("i"){
                    // Add show subcommands for UserMode as suggestions
                    let show_options = vec!["id"];
                    for option in show_options {
                        candidates.push(Pair {
                            display: format!("{}", option),
                            replacement: format!("{}", option),
                        });
                    
                    }
                }
                else if parts.len() == 4 && parts[0] == "enable" && parts[3].starts_with("r"){
                    // Add show subcommands for UserMode as suggestions
                    let show_options = vec!["router"];
                    for option in show_options {
                        candidates.push(Pair {
                            display: format!("{}", option),
                            replacement: format!("{}", option),
                        });
                    
                    }
                }
                else if parts.len() == 5 && parts[0] == "do" {
                    // Add show subcommands for UserMode as suggestions
                    let show_options = vec!["brief"];
                    for option in show_options {
                        candidates.push(Pair {
                            display: format!("{}", option),
                            replacement: format!("{}", option),
                        });
                    
                    }
                }
                else if parts.len() == 6 && parts[0] == "add" {
                    // Add show subcommands for UserMode as suggestions
                    let show_options = vec!["router"];
                    for option in show_options {
                        candidates.push(Pair {
                            display: format!("{}", option),
                            replacement: format!("{}", option),
                        });
                    
                    }
                }
            }
        }

        let new_pos = if parts.len() > 1 {
            query.rfind(' ').unwrap_or(0) + 1
        } else {
            0
        };

        Ok((new_pos, candidates))
    }
}


/// Determines if a command is allowed in the current CLI mode.
///
/// This function checks whether a given command is valid and permitted for execution
/// in the specified CLI mode. Each mode has a predefined set of commands that are allowed.
///
/// # Arguments
/// - `command`: A reference to a `String` representing the command to check.
/// - `mode`: A reference to the current `Mode` in which the CLI is operating.
///
/// # Returns
/// - `true` if the command is allowed in the given mode.
/// - `false` if the command is not allowed in the given mode.
///
/// # Supported Modes and Commands
/// - **UserMode**: Basic commands like `enable`, `exit`, `help`, and `ping`.
/// - **PrivilegedMode**: Advanced commands like `configure`, `write`, `copy`, `show`, and others.
/// - **ConfigMode**: Configuration commands like `hostname`, `interface`, `ip`, and more.
/// - **InterfaceMode**: Interface-specific commands like `shutdown`, `switchport`, `ip`, etc.
/// - **VlanMode**: VLAN-specific commands like `name`, `state`, and `vlan`.
/// - **RouterConfigMode**: Router configuration commands like `network`, `neighbor`, and `area`.
/// - **ConfigStdNaclMode**: Standard ACL commands like `deny`, `permit`, and `ip`.
/// - **ConfigExtNaclMode**: Extended ACL commands like `deny`, `permit`, and `ip`.
///
/// # Example
/// ```rust
/// let command = "enable".to_string();
/// let mode = Mode::UserMode;
///
/// if is_command_allowed_in_mode(&command, &mode) {
///     println!("Command '{}' is allowed in {:?} mode.", command, mode);
/// } else {
///     println!("Command '{}' is not allowed in {:?} mode.", command, mode);
/// }
/// ```
///
/// # Notes
/// - Modes not explicitly defined in the match statement will return `false` for all commands.
/// - The `Mode` enum may include additional modes that are not currently covered.
///
/// # Performance
/// The function uses the `matches!` macro to provide concise and efficient pattern matching
/// for the commands within each mode.
fn is_command_allowed_in_mode(command: &String, mode: &Mode) -> bool {
    match mode {
        Mode::UserMode => matches!(command.as_str(), "enable" | "do" | "disable" | "traceroute" | "connect" | "reload" | "poweroff" | "exit" | "clear" | "help" | "show" | "dhcp_enable" | "ping" | "write" | "ifconfig" | "ip"),
        Mode::PrivilegedMode => matches!(command.as_str(), "config" | "do" | "ssh" | "disable" | "traceroute" | "connect" | "reload" | "poweroff" | "debug" | "undebug" | "exit" | "clear" | "help" | "write" | "copy" | "clock" | "dhcp_enable" | "ping" | "show" | "ifconfig" | "ip"),
        Mode::ConfigMode => matches!(command.as_str(), "config" | "enable" | "hostname" | "do" | "interface" | "connect" | "disable" | "traceroute" | "reload" | "poweroff" | "no" | "exit" | "clear" | "help" | "write" | "dhcp_enable" | "ping" | "enable" | "service" | "set" | "ifconfig" | "ntp" | "ip" | "sdm" |"bitd" | "ptm" | "rtxc" | "infodist" | "sysmon" | "high_availability"),
        Mode::InterfaceMode => matches!(command.as_str(), "exit" | "disable" | "do" | "reload" | "poweroff" | "shutdown" | "no" | "clear" | "help" | "write" | "interface" | "ip" ),
        Mode::VlanMode => matches!(command.as_str(), "config" | "enable" | "disable" | "exit" | "do" | "reload" | "poweroff" | "clear" | "help" | "bridge_name" | "vlan" | "segment" | "add" | "router" ), 
        Mode::QosMode => matches!(command.as_str(), "config" | "enable" | "disable" | "exit" | "do" | "reload" | "poweroff" | "clear" | "help" | "policy" | "priority" | "interface" ),
        Mode::DynamicRMode => matches!(command.as_str(), "config" | "enable" | "disable" | "exit" | "do" | "reload" | "poweroff" | "clear" | "help" | "network" | "redistribute" | "valid" | "controller"),
        Mode::PortSMode => matches!(command.as_str(), "config" | "enable" | "disable" | "exit" | "do" | "reload" | "poweroff" | "clear" | "help" | "mode" | "violation_status"  | "max_devices" ),
        Mode::MonitoringMode => matches!(command.as_str(), "config" | "enable" | "disable" | "exit" | "do" | "reload" | "poweroff" | "clear" | "help" | "logging_level"),
        Mode::AutoDMode => matches!(command.as_str(), "config" | "enable" | "disable" | "exit" | "do" | "reload" | "poweroff" | "clear" | "help" |"holdtime" |"reinit" |"interface"),
        
    }
}


/// Implements the `Helper` trait for the `CommandCompleter` struct.
impl Helper for CommandCompleter {}

/// Implements the `Hinter` trait for the `CommandCompleter` struct.
impl Hinter for CommandCompleter {
    type Hint = String;

    /// Provides hints for the current input line.
    ///
    /// # Arguments
    /// - `_line`: The current input line from the user.
    /// - `_pos`: The cursor position within the line.
    /// - `_ctx`: The rustyline context.
    ///
    /// # Returns
    /// Always returns `None` in this implementation as hints are not used.
    fn hint(&self, _line: &str, _pos: usize, _ctx: &rustyline::Context<'_>) -> Option<String> {
        None 
    }
}

/// Implements the `Highlighter` trait for the `CommandCompleter` struct.
impl Highlighter for CommandCompleter {}


/// Implements the `Validator` trait for the `CommandCompleter` struct.
impl Validator for CommandCompleter {

    /// Validates the current input line.
    ///
    /// # Arguments
    /// - `_ctx`: A mutable reference to the validation context.
    ///
    /// # Returns
    /// Always returns `ValidationResult::Valid` in this implementation.
    fn validate(
        &self,
        _ctx: &mut ValidationContext<'_>,
    ) -> Result<ValidationResult, ReadlineError> {
        Ok(ValidationResult::Valid(None)) 
    }
}