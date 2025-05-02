/// External crates for the CLI application
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::Path;
use std::fs::File;
use std::fs;
use std::io::Write;
use rpassword::read_password;
use std::process::Command as ProcessCommand;

use crate::run_config::{get_running_config, help_command, save_running_to_startup};
use crate::execute::Command;
use crate::cliconfig::CliContext;
use crate::execute::Mode;
use crate::clock_settings::{handle_clock_set, parse_clock_set_input};
use crate::network_config::{terminate_ssh_session, get_available_int, ip_with_cidr, get_system_interfaces, connect_via_ssh, execute_spawn_process, STATUS_MAP, IP_ADDRESS_STATE,  SELECTED_INTERFACE, ROUTE_TABLE};
use crate::network_config::NtpAssociation;
use crate::passwd::{PASSWORD_STORAGE, set_enable_password, set_enable_secret, get_enable_password, get_enable_secret, encrypt_password};
use crate::show_c::{show_clock, show_uptime, show_version, show_sessions, show_controllers, show_history, show_run_conf, show_start_conf, show_interfaces, show_ip_int_br, show_ip_int_sp, show_ip_route, show_login, show_ntp, show_ntp_asso, show_proc, show_arp};

/// Builds and returns a `HashMap` of available commands, each represented by a `Command` structure.
/// 
/// This function initializes a registry of commands that can be executed in different modes
/// (e.g., `UserMode`, `PrivilegedMode`, `ConfigMode`, etc.) within a router-like system.
/// Each command is associated with a name, description, suggestions for usage, and an execution
/// function that defines its behavior.
///
/// 
/// # Returns
/// A `HashMap` where the keys are command names (as `&'static str`) and the values are the corresponding `Command` structs.
/// Each `Command` struct contains the `name`, `description`, `suggestions`, and an `execute` function.
pub fn build_command_registry() -> HashMap<&'static str, Command> {
    let mut commands = HashMap::new();

    //Enter the Priviledged Exec Mode (Enable password and secret in Global Configuration mode)
    commands.insert("enable", Command {
        name: "enable",
        description: "Enter privileged EXEC mode",
        suggestions: Some(vec!["password", "secret"]),
        suggestions1: None,
        suggestions2: None,
        options: Some(vec!["<password>      - Enter the password>",
        "<secret>       - Enter the secret>"]),
        execute: |args, context, _| {
            if args.is_empty(){
                if matches!(context.current_mode, Mode::UserMode) {

                    let stored_password = get_enable_password();
                    let stored_secret = get_enable_secret();

                    fn proceed_to_priv_mode(context: &mut CliContext){
                        context.current_mode = Mode::PrivilegedMode;
                        context.prompt = format!("{}#", context.config.hostname);
                        println!("Entering privileged EXEC mode...");
                    }
        
                    if stored_password.is_none() && stored_secret.is_none() {
                        // No passwords stored, directly go to privileged EXEC mode
                        proceed_to_priv_mode(context);
                        return Ok(());
                    }
        
                    // Prompt for the enable password
                    if stored_secret.is_none() && stored_password.is_some() {
                        println!("Enter password:");
                        let input_password = read_password().unwrap_or_else(|_| "".to_string());
                        let hashed_input = encrypt_password(&input_password);
            
                        if let Some(ref stored_password) = stored_password {
                            if hashed_input == *stored_password {
                                // Correct enable password, proceed to privileged mode
                                proceed_to_priv_mode(context);
                                return Ok(());
                            }
                        }
                        return Err("Incorrect password.".into());
                    }

                    if stored_password.is_none() && stored_secret.is_some(){
                        println!("Enter secret:");
                        let input_secret= read_password().unwrap_or_else(|_| "".to_string());
                        let hashed_input = encrypt_password(&input_secret);
            
                        if let Some(ref stored_secret) = stored_secret {
                            if hashed_input == *stored_secret {
                                // Correct enable password, proceed to privileged mode
                                proceed_to_priv_mode(context);
                                return Ok(());
                            }
                        }
                        return Err("Incorrect secret.".into());
                    }
            
                    // If secret is stored, prompt for it if password check fails
                    if stored_password.is_some() && stored_secret.is_some() {
                        println!("Enter password:");
                        let input_password = read_password().unwrap_or_else(|_| "".to_string());
                        println!("Enter secret:");
                        let input_secret = read_password().unwrap_or_else(|_| "".to_string());

                        // Hash both inputs
                        let hashed_password = encrypt_password(&input_password);
                        let hashed_secret = encrypt_password(&input_secret);
        
                        if let (Some(ref stored_secrets), Some(ref stored_passwords)) = 
                                (stored_secret, stored_password) {
                            if hashed_secret == *stored_secrets && hashed_password == *stored_passwords {
                                // Both correct, proceed to privileged mode
                                proceed_to_priv_mode(context);
                                return Ok(());
                            }
                        }
                        return Err("Incorrect password or secret.".into());
                    }
        
                    // If neither password nor secret matches, return an error
                    Err("Incorrect password or secret.".into())
                } else {
                    Err("The 'enable' command is only available in User EXEC mode.".into())
                }
            } else {
                match &args[0][..]{
                    "password" => {
                        if matches!(context.current_mode, Mode::ConfigMode) {
                            if args.len() != 2 {
                                Err("You must provide the enable password.".into())
                            } else {
                                let password = &args[1];
                                let hashed_password = encrypt_password(password);
                                set_enable_password(&hashed_password);
                                context.config.enable_password = Some(password.to_string());
                                println!("Enable password set.");
                                Ok(())
                            }
                        } else {
                            Err("The 'enable password' command is only available in Config mode.".into())
                        }
                    },
                    "secret" => {
                        if matches!(context.current_mode, Mode::ConfigMode) {
                            if args.len() != 2 {
                                Err("You must provide the enable secret password.".into())
                            } else {
                                let secret = &args[1];
                                let hashed_secret = encrypt_password(secret);
                                set_enable_secret(&hashed_secret);
                                context.config.enable_secret = Some(secret.to_string());
                                println!("Enable secret password set.");
                                Ok(())
                            }
                        } else {
                            Err("The 'enable secret' command is only available in Config mode.".into())
                        }
                    },
                    _=> Err(format!("Unknown enable subcommand: {}", args[0]).into())
                }
            }
        },
    });

    //Enter the Global Configuration Mode
    commands.insert("configure", Command {
        name: "configure terminal",
        description: "Enter global configuration mode",
        suggestions: Some(vec!["terminal"]),
        suggestions1: Some(vec!["terminal"]),
        suggestions2: None,
        options: None,
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::PrivilegedMode) {
                if args.len() == 1 && args[0] == "terminal" {
                    context.current_mode = Mode::ConfigMode;
                    context.prompt = format!("{}(config)#", context.config.hostname);
                    println!("Enter configuration commands, one per line.  End with CNTL/Z");
                    Ok(())
                } else {
                    Err("Invalid arguments provided to 'configure terminal'. This command does not accept additional arguments.".into())
                }
            } else {
                Err("The 'configure terminal' command is only available in Privileged EXEC mode.".into())
            }
        },
    });

    //Enter the Interface Configuration Mode
    commands.insert("interface", Command {
        name: "interface",
        description: "Enter Interface configuration mode",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: Some(vec!["<interface-name>    - Specify a valid interface name"]),
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::ConfigMode | Mode::InterfaceMode) {
                
                let (interface_list, interfaces_list) = match get_available_int() {
                    Ok(list) => list,
                    Err(e) => return Err(e),
                };
                
                //let args: Vec<String> = std::env::args().skip(1).collect();
                if args.is_empty() {
                    return Err(format!("Please specify a valid interface. Available interfaces: {}", interfaces_list));
                }
    
                if args.len() == 1 {
                    let net_interface = &args[0];
                    if interface_list.iter().any(|i| i == net_interface) {
                        context.current_mode = Mode::InterfaceMode;
                        context.selected_interface = Some(net_interface.to_string());
                        context.prompt = format!("{}(config-if)#", context.config.hostname);
                        println!("Entering Interface configuration mode for: {}", net_interface);

                        // Store the selected interface globally
                        let mut selected = SELECTED_INTERFACE.lock().unwrap();
                        *selected = Some(net_interface.to_string());

                        Ok(())
                    } else {
                        Err(format!("Invalid interface: {}. Available interfaces: {}", net_interface, interfaces_list))
                    }
                } else {
                    Err(format!("Invalid number of arguments. Usage: interface <interface-name>").into())
                }
            } else {
                Err("The 'interface' command is only available in Global Configuration mode and interface configuration mode.".into())
            }
        },
    });

    //---------------------------------------------------------------------------------------------------------------------------------
    
    /*Enter Modes for Management purposes:
    SDMMode;
    BITDMode;
    TPMMode;
    RTxCMode;
    InfoDistMode;
    SysMonitorMode
    HighAvaMode;*/

    commands.insert("sdm", Command {
        name: "SDM",
        description: "Enter Software and Database Management Mode",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: None,
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::ConfigMode) {
                if args.is_empty() {
                    context.current_mode = Mode::SDMMode;
                    context.prompt = format!("{}(config-SDM)#", context.config.hostname);
                    println!("Entering the Software and Database Management Mode");
                    Ok(())
                } else {
                    Err("Invalid command.".into())
                }
                
            } else {
                Err("The 'sdm' command is only available in Global Configuration mode.".into())
            }
        },
    });

    commands.insert("bitd", Command {
        name: "BITD",
        description: "Enter SBuilt-In Test and Diagnostics Mode",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: None,
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::ConfigMode) {
                if args.is_empty() {
                    context.current_mode = Mode::BITDMode;
                    context.prompt = format!("{}(config-BITD)#", context.config.hostname);
                    println!("Entering the Built-In Test and Diagnostics Mode");
                    Ok(())
                } else {
                    Err("Invalid command.".into())
                }
                
            } else {
                Err("The 'bitd' command is only available in Global Configuration mode.".into())
            }
        },
    });

    commands.insert("ptm", Command {
        name: "PTM",
        description: "Enter Position and Time Management Mode",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: None,
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::ConfigMode) {
                if args.is_empty() {
                    context.current_mode = Mode::TPMMode;
                    context.prompt = format!("{}(config-PTM)#", context.config.hostname);
                    println!("Entering the Position and Time Management Mode");
                    Ok(())
                } else {
                    Err("Invalid command.".into())
                }
                
            } else {
                Err("The 'ptm' command is only available in Global Configuration mode.".into())
            }
        },
    });

    commands.insert("rtxc", Command {
        name: "RTxC",
        description: "Enter Radio Transmission Control Mode",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: None,
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::ConfigMode) {
                if args.is_empty() {
                    context.current_mode = Mode::RTxCMode;
                    context.prompt = format!("{}(config-RTxC)#", context.config.hostname);
                    println!("Entering the Radio Transmission Control Mode");
                    Ok(())
                } else {
                    Err("Invalid command.".into())
                }
                
            } else {
                Err("The 'rtxc' command is only available in Global Configuration mode.".into())
            }
        },
    });

    commands.insert("infodist", Command {
        name: "Information Distribution",
        description: "Enter Information Distribution Mode",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: None,
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::ConfigMode) {
                if args.is_empty() {
                    context.current_mode = Mode::InfoDistMode;
                    context.prompt = format!("{}(config-InformationD)#", context.config.hostname);
                    println!("Entering the Information Distribution Mode");
                    Ok(())
                } else {
                    Err("Invalid command.".into())
                }
                
            } else {
                Err("The 'infodist' command is only available in Global Configuration mode.".into())
            }
        },
    });

    commands.insert("sysmon", Command {
        name: "System Monitoring",
        description: "Enter System Monitoring Mode",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: None,
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::ConfigMode) {
                if args.is_empty() {
                    context.current_mode = Mode::SysMonitorMode;
                    context.prompt = format!("{}(config-SysMon)#", context.config.hostname);
                    println!("Entering the System Monitoring Mode");
                    Ok(())
                } else {
                    Err("Invalid command.".into())
                }
                
            } else {
                Err("The 'sysmon' command is only available in Global Configuration mode.".into())
            }
        },
    });

    commands.insert("high_availability", Command {
        name: "High Availability Config Mode",
        description: "Enter High Availability Config Mode",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: None,
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::ConfigMode) {
                if args.is_empty() {
                    context.current_mode = Mode::HighAvaMode;
                    context.prompt = format!("{}(config-HighAva)#", context.config.hostname);
                    println!("Entering the High Availability Config Mode");
                    Ok(())
                } else {
                    Err("Invalid command.".into())
                }
                
            } else {
                Err("The 'high_availability' command is only available in Global Configuration mode.".into())
            }
        },
    });
    //-------------------------------------------------------------------------------------------------------------------------------

    //Connect to the Network Processor, SEM module and Katim VM via SSH
    commands.insert("connect", Command {
        name: "connect",
        description: "Connect to network processor or crypto module",
        suggestions: Some(vec!["network", "crypto", "katim"]),
        suggestions1: Some(vec!["network", "crypto", "katim"]),
        suggestions2: None,
        options: None,
        execute: |args, context, _| {    
            if args.len() != 1 {
                return Err("Invalid number of arguments. Usage: connect <network|crypto>".into());
            }
    
            match args[0] {
                "katim" => {
                    println!("Connecting to Katim's VM...");
                    //connect_via_ssh("root", "192.168.x.x")?;   //Add the actual user credentials
                    println!("Connected successfully! Exiting...");
                    Ok(())
                },
                "network" => {
                    println!("Connecting to network processor...");
                    //connect_via_ssh("pnfcli", "192.168.253.146")?; //Replace with actual details of NP
                    //connect_via_ssh("root", "192.168.101.100")?;    //OpenWRT VM
                    context.current_mode = Mode::NetworkProcessor;
                    context.prompt = format!("Network>");
                    println!("Connected successfully!");
                    Ok(())
                },
                "crypto" => {
                    println!("Connecting to crypto module...");
                    //connect_via_ssh("pnfcli", "192.168.253.147")?; //Replace with actual details of SEM
                    context.current_mode = Mode::Sem;
                    context.prompt = format!("SEM>");
                    println!("Connected successfully!");
                    Ok(())
                },
                _ => Err("Invalid argument. Use 'network' or 'crypto'".into())
            }
        },
    });

    //Exit each and every mode and enter its parent mode
    commands.insert("exit", Command {
        name: "exit",
        description: "Exit the current mode and return to the previous mode.",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: None,
        execute: |args, context, _| {
            if args.is_empty() {
                match context.current_mode {
                                       
                    Mode::InterfaceMode => {
                        context.current_mode = Mode::ConfigMode;
                        context.prompt = format!("{}(config)#", context.config.hostname);
                        println!("Exiting Interface Configuration Mode...");
                        Ok(())
                    }
                    Mode::SDMMode => {
                        context.current_mode = Mode::ConfigMode;
                        context.prompt = format!("{}(config)#", context.config.hostname);
                        println!("Exiting Software and Database Management Mode...");
                        Ok(())
                    }
                    Mode::BITDMode => {
                        context.current_mode = Mode::ConfigMode;
                        context.prompt = format!("{}(config)#", context.config.hostname);
                        println!("Exiting Built-In Test and Diagnostics Mode...");
                        Ok(())
                    }
                    Mode::TPMMode => {
                        context.current_mode = Mode::ConfigMode;
                        context.prompt = format!("{}(config)#", context.config.hostname);
                        println!("Exiting Position and Time Management Mode...");
                        Ok(())
                    }
                    Mode::RTxCMode => {
                        context.current_mode = Mode::ConfigMode;
                        context.prompt = format!("{}(config)#", context.config.hostname);
                        println!("Exiting Radio Transmission Control Mode...");
                        Ok(())
                    }
                    Mode::InfoDistMode => {
                        context.current_mode = Mode::ConfigMode;
                        context.prompt = format!("{}(config)#", context.config.hostname);
                        println!("Exiting Information Distribution Mode...");
                        Ok(())
                    }
                    Mode::SysMonitorMode => {
                        context.current_mode = Mode::ConfigMode;
                        context.prompt = format!("{}(config)#", context.config.hostname);
                        println!("Exiting System Monitoring Mode...");
                        Ok(())
                    }
                    Mode::HighAvaMode => {
                        context.current_mode = Mode::ConfigMode;
                        context.prompt = format!("{}(config)#", context.config.hostname);
                        println!("Exiting High availability Config Mode...");
                        Ok(())
                    }
                    Mode::ConfigMode => {
                        context.current_mode = Mode::PrivilegedMode;
                        context.prompt = format!("{}#", context.config.hostname);
                        println!("Exiting Global Configuration Mode...");
                        Ok(())
                    }
                    Mode::PrivilegedMode => {
                        context.current_mode = Mode::UserMode;
                        context.prompt = format!("{}>", context.config.hostname);
                        println!("Exiting Privileged EXEC Mode...");
                        Ok(())
                    }
                    Mode::UserMode => {
                        println!("Already at the top level. No mode to exit.");
                        Err("No mode to exit.".into())
                    }
                    Mode::NetworkProcessor => {
                        context.current_mode = Mode::UserMode;
                        context.prompt = format!("{}>", context.config.hostname);
                        println!("Exiting Privileged EXEC Mode...");
                        Ok(())
                    }
                    Mode::Sem => {
                        context.current_mode = Mode::UserMode;
                        context.prompt = format!("{}>", context.config.hostname);
                        println!("Exiting Privileged EXEC Mode...");
                        Ok(())
                    }
                    
                }
            } else if args.len() == 1 && args[0] == "ssh" {
                println!("Terminating SSH session...");
                terminate_ssh_session();
                Ok(())
            }
            else {
                Err("Command is either 'exit' , 'exit cli' or 'exit ssh'".into())
            }
        },
    });

    //Enter the User Exec Mode from the Priviledged Exec Mode
    commands.insert("disable", Command {
        name: "disable",
        description: "Exit the Privileged EXEC mode and return to the USER EXEC mode.",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: None,
        execute: |_args, context, _| {
            if _args.is_empty() {
                match context.current_mode {
                    Mode::ConfigMode | Mode::InterfaceMode | Mode:: SDMMode | Mode:: BITDMode | Mode:: TPMMode | Mode:: RTxCMode | Mode:: InfoDistMode | Mode:: SysMonitorMode | Mode:: HighAvaMode | Mode::NetworkProcessor | Mode::Sem => {
                        println!("This command only works at the Privileged Mode.");
                        Err("This command only works at the Privileged Mode.".into())
                    
                    }
                    
                    Mode::PrivilegedMode => {
                        context.current_mode = Mode::UserMode;
                        context.prompt = format!("{}>", context.config.hostname);
                        println!("Exiting Privileged EXEC Mode...");
                        Ok(())
                    }
                    Mode::UserMode => {
                        println!("Already at the top level. No mode to exit.");
                        Err("No mode to exit.".into())
                    }
                }
            } else {
                Err("Invalid arguments provided to 'exit'. This command does not accept additional arguments.".into())
            }
        },
    });

    //Reboot the system
    commands.insert("reload", Command {
        name: "reload",
        description: "Reload the system",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: None,
        execute: |_, _, _| {
    
            println!("Proceed with reload? [yes/no]:");
            let mut reload_confirm = String::new();
            std::io::stdin().read_line(&mut reload_confirm).expect("Failed to read input");
            let reload_confirm = reload_confirm.trim();
    
            if ["yes", "y", ""].contains(&reload_confirm.to_ascii_lowercase().as_str()) {
                  
                execute_spawn_process("sudo", &["reboot"]);
                Ok(())
                
            } else if ["no", "n"].contains(&reload_confirm.to_ascii_lowercase().as_str()) {
                println!("Reload aborted.");
                Ok(())
            } else {
                Err("Invalid input. Please enter 'yes', 'y', or 'no'.".into())
            }
        },
    });

    //Shutdown the system
    commands.insert("poweroff", Command {
        name: "poweroff",
        description: "Shutdown the Management PC",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: None,
        execute: |_, _, _| {
    
            println!("Do you want to shutdown the PC? [yes/no]:");
            let mut reload_confirm = String::new();
            std::io::stdin().read_line(&mut reload_confirm).expect("Failed to read input");
            let reload_confirm = reload_confirm.trim();
    
            if ["yes", "y", ""].contains(&reload_confirm.to_ascii_lowercase().as_str()) {
                fs::remove_file("history.txt");  
                execute_spawn_process("sudo", &["shutdown", "now"]);
                Ok(())
                
            } else if ["no", "n"].contains(&reload_confirm.to_ascii_lowercase().as_str()) {
                println!("Reload aborted.");
                Ok(())
            } else {
                Err("Invalid input. Please enter 'yes', 'y', or 'no'.".into())
            }
        },
    });
    
    //Debug the processes
    commands.insert("debug", Command {
        name: "debug all",
        description: "To turn on all the possible debug levels",
        suggestions: Some(vec!["all"]),
        suggestions1: Some(vec!["all"]),
        suggestions2: None,
        options: None,
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::PrivilegedMode) {
                if args.len() == 1 && args[0] == "all" {
                    println!("This may severely impact network performance. Continue? (yes/[no]):");
    
                    let mut save_input = String::new();
                    std::io::stdin().read_line(&mut save_input).expect("Failed to read input");
                    let save_input = save_input.trim();
            
                    if ["yes", "y", ""].contains(&save_input.to_ascii_lowercase().as_str()) {
                        println!("All possible debugging has been turned on");
                        //Execution must be provided
                        Ok(())
                    } else if ["no", "n"].contains(&save_input.to_ascii_lowercase().as_str()){
                        println!("Returned");
                        //Execution must be provided
                        Ok(())
                    } else {
                        return Err("Invalid input. Please enter 'yes' or 'no'.".into());
                    }
                } else {
                    Err("Invalid arguments provided to 'debug all'. This command does not accept additional arguments.".into())
                }
            } else {
                Err("The 'debug all' command is only available in Privileged EXEC mode.".into())
            }
        },
    });

    //Stop the debugging process
    commands.insert("undebug", Command {
        name: "undebug all",
        description: "Turning off all possible debugging processes",
        suggestions: Some(vec!["all"]),
        suggestions1: Some(vec!["all"]),
        suggestions2: None,
        options: None,
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::PrivilegedMode) {
                if args.len() == 1 && args[0] == "all" {
                    println!("All possible debugging has been turned off");
                    Ok(())
                } else {
                    Err("Invalid arguments provided to 'undebug all'. This command does not accept additional arguments.".into())
                }
            } else {
                Err("The 'undebug all' command is only available in Privileged EXEC mode.".into())
            }
        },
    });

    //Change the hostname if needed
    commands.insert("hostname", Command {
        name: "hostname",
        description: "Set the device hostname",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: Some(vec!["<new-hostname>    - Enter a new hostname"]),
        execute: |args, context, _| {
            if let Mode::ConfigMode = context.current_mode {
                if let Some(new_hostname) = args.get(0) {
                    let is_valid = new_hostname.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-') && 
                                new_hostname.chars().next().map_or(false, |c| c.is_alphabetic());
                    
                    if is_valid {
                        context.config.hostname = new_hostname.to_string();

                        match context.current_mode {
                            Mode::ConfigMode => {
                                context.prompt = format!("{}(config)#", new_hostname);
                            }
                            Mode::PrivilegedMode => {
                                context.prompt = format!("{}#", new_hostname);
                            }
                            _ => {
                                context.prompt = format!("{}>", new_hostname);
                            }
                        }

                        println!("Hostname changed to '{}'", new_hostname);
                        Ok(())
                    } else {
                        Err("Invalid hostname format. Hostname must start with a letter and contain only letters, numbers, underscores, or hyphens.".into())
                    }
                } else {
                    Err("Please specify a new hostname. Usage: hostname <new_hostname>".into())
                }
            } else {
                Err("The 'hostname' command is only available in Global Configuration Mode.".into())
            }
        },
    });

    //Check the interface details
    commands.insert(
        "ifconfig",
        Command {
            name: "ifconfig",
            description: "Configure a network interface",
            suggestions: None,
            suggestions1: None,
            suggestions2: None,
            options: Some(vec![
                "<interface>         - Network interface name"
            ]),
            execute: |args, _, _| {
                // Display all interfaces if no arguments
                if args.is_empty() {
                    println!("System Network Interfaces:");
                    println!("-------------------------");
                    println!("{}", get_system_interfaces(None));
                    
                    return Ok(());
                } else {
                    // Get details for the specified interface
                    let interface_name = &args[0];
                    println!("Interface: {}", interface_name);
                    println!("-------------------------");
                    
                    // Get the specified interface details
                    let interface_details = get_system_interfaces(Some(interface_name));
                    
                    if interface_details.is_empty() {
                        println!("Interface '{}' not found.", interface_name);
                    } else {
                        println!("{}", interface_details);
                    }
                }
    
                Ok(())
            },
        },
    );

    //---------------------------------------------------------------------------------------------------------------------------------
    //Show commands
    commands.insert(
        "show",
        Command {
            name: "show",
            description: "Display all the show commands when specific command is passed in the specific mode",
            suggestions: Some(vec![
                "running-config",
                "startup-config",
                "version",
                "ntp",
                "processes",
                "clock",
                "uptime",
                "controllers",
                "history",
                "sessions",
                "interfaces",
                "ip",
                "login",
                "arp"
            ]),
            suggestions1: None,
            suggestions2: Some(vec!["interface", "brief", "associations"]),
            options: None,
            execute: |args, context, clock| {
                if matches!(context.current_mode, Mode::UserMode | Mode ::PrivilegedMode){
                    return match args.get(0) {
                        Some(&"clock") => {
                            show_clock(clock);
                            Ok(())
                        },
                        Some(&"uptime") => {
                            show_uptime(clock);
                            Ok(())
                        },
                        Some(&"version") => {
                            show_version();
                            Ok(())
                        },
                        
                        Some(&"sessions") if matches!(context.current_mode, Mode::UserMode) => {
                            show_sessions();
                            Ok(())
                        },

                        Some(&"controllers") if matches!(context.current_mode, Mode::UserMode) => {
                            
                            show_controllers();  
                            Ok(())
                        },
                        Some(&"history")  => {
                            show_history();
                            Ok(())
                        },
                        
                        Some(&"running-config") if matches!(context.current_mode, Mode::PrivilegedMode) => {
                            show_run_conf(&context);
                            Ok(())
                        },

                        Some(&"startup-config") if matches!(context.current_mode, Mode::PrivilegedMode) => {
                            show_start_conf(&context);
                            Ok(())
                        },

                        Some(&"interfaces") if matches!(context.current_mode, Mode::PrivilegedMode) => {
                            show_interfaces();
                            Ok(())
                        },

                        Some(&"ip") if matches!(context.current_mode, Mode::PrivilegedMode) => {
                            match args.get(1) {
                                Some(&"interface") => {
                                    match args.get(2) {
                                        Some(&"brief") => {
                                            show_ip_int_br();
                                            Ok(())
                                        },
                                        Some(&interface) => {
                                            // Verify the interface exists before showing its details
                                            match get_available_int() {
                                                Ok((interface_list, _)) => {
                                                    if interface_list.iter().any(|i| i == interface) {
                                                        show_ip_int_sp(interface)?;
                                                        Ok(())
                                                    } else {
                                                        Err(format!("Interface '{}' not found. Available interfaces: {}", 
                                                            interface, 
                                                            interface_list.join(", ")))
                                                    }
                                                },
                                                Err(e) => Err(e),
                                            }
                                        },
                                        _ => Err("Invalid interface subcommand. Use 'brief'".into())
                                    }
                                }
                                Some(&"route") => {
                                    show_ip_route();
                                    Ok(())
                                }
                                _ => Err("Invalid IP subcommand. Use 'interface brief'".into())
                            }
                        },

                        Some(&"login") if matches!(context.current_mode, Mode::PrivilegedMode) => {
                            show_login();
                            Ok(())
                        },
                        
                        Some(&"ntp") if matches!(context.current_mode, Mode::PrivilegedMode) => {
                            match args.get(1) {
                                Some(&"associations") => {
                                    show_ntp_asso(&context);
                                    Ok(())
                                },
                                None => {
                                    show_ntp(&context);
                                    Ok(())
                                },
                                _ => Err("Invalid NTP subcommand. Use 'associations' or no subcommand".into())
                            }
                        },
                        
                        Some(&"processes") if matches!(context.current_mode, Mode::PrivilegedMode) => {
                            show_proc();
                            Ok(())
                            
                            
                        },
                        Some(&"arp") => {
                            show_arp();
                            Ok(())    
                        },
                        
                        Some(cmd) => {
                            println!("Invalid show command: {}", cmd);
                            Ok(())
                        },

                        None => {
                            println!("Missing parameter. Usage: show <command>");
                            Ok(())
                        }
                    }

                }
                else {
                    return Err("Show commands are only available in User EXEC mode and Privileged EXEC mode.".into());
                }
            },
        },
    );

    commands.insert(
        "do",
        Command {
            name: "do",
            description: "Execute privileged EXEC commands from any configuration mode",
            suggestions: Some(vec!["show", "copy", "clock", "debug", "undebug", "clear"]),
            suggestions1: Some(vec!["show", "copy", "clock", "debug", "undebug", "clear"]),
            suggestions2: Some(vec![
                "running-config",
                "startup-config",
                "version",
                "ntp",
                "processes",
                "clock",
                "uptime",
                "controllers",
                "history",
                "sessions",
                "ip",
                "interfaces",
                "login",
                "arp"

            ]),
            options: None,
            execute: |args, context, clock| {
                // Check if the first argument is "show"
                match args.get(0) {
                    Some(&"show") => {
                        let show_args: Vec<&str> = args.iter().skip(1).copied().collect();
                        
                        match show_args.get(0) {
                            Some(&"clock") => {
                                show_clock(clock);
                                Ok(())
                            },
                            Some(&"uptime") => {
                                show_uptime(clock);
                                Ok(())
                            },
                            Some(&"version") => {
                                show_version();
                                Ok(())
                            },
                            Some(&"sessions") => {
                                show_sessions();
                                Ok(())
                            },
                            Some(&"controllers") => {
                                show_controllers();                                
                                Ok(())
                            },
                            Some(&"history") => {
                                show_history();
                                Ok(())
                            },
                            Some(&"running-config") => {
                                show_run_conf(&context);
                                Ok(())
                            },
                            Some(&"startup-config") => {
                                show_start_conf(&context);
                                Ok(())
                            },
                            Some(&"interfaces") => {
                                show_interfaces();
                                Ok(())
                            },
                            Some(&"ip") => {
                                match args.get(2) {
                                    Some(&"interface") => {
                                        match args.get(3) {
                                            Some(&"brief") => {
                                                show_ip_int_br();
                                                Ok(())
                                            },
                                            Some(&interface) => {
                                                // Verify the interface exists before showing its details
                                                match get_available_int() {
                                                    Ok((interface_list, _)) => {
                                                        if interface_list.iter().any(|i| i == interface) {
                                                            show_ip_int_sp(interface)?;
                                                            Ok(())
                                                        } else {
                                                            Err(format!("Interface '{}' not found. Available interfaces: {}", 
                                                                interface, 
                                                                interface_list.join(", ")))
                                                        }
                                                    },
                                                    Err(e) => Err(e),
                                                }
                                            },
                                            _ => Err("Invalid interface subcommand. Use 'brief'".into())
                                        }
                                    }
                                    Some(&"route") => {
                                        show_ip_route();
                                        Ok(())
                                    }
                                    _ => Err("Invalid IP subcommand. Use 'interface brief'".into())
                                }
                            },
                            Some(&"login") => {
                                show_login();
                                Ok(())
                            },
                            Some(&"ntp") => {
                                match show_args.get(1) {
                                    Some(&"associations") => {
                                        show_ntp_asso(&context);
                                        Ok(())
                                    },
                                    None => {
                                        show_ntp(&context);
                                        Ok(())
                                    },
                                    _ => Err("Invalid NTP subcommand. Use 'associations' or no subcommand".into())
                                }
                            },
                            Some(&"processes") => {
                                show_proc();
                                Ok(())
                            },
                            Some(&"arp") => {
                                show_arp();
                                Ok(())
                            },
                            
                            Some(cmd) => {
                                println!("Invalid show command: {}", cmd);
                                Ok(())
                            },
                            None => {
                                println!("Missing parameter. Usage: do show <command>");
                                Ok(())
                            }
                        }
                    },
                    Some(&"copy") => {
                        if args.len() < 3 || args[1] != "running-config" {
                            println!("Usage: copy running-config startup-config|<file-name>");
                            return Ok(());
                        }
                        
                        let running_config = get_running_config(context);
                        let destination = &args[2];
                        
                        copy_run_config(&running_config, destination, context)
                    },
                    Some(&"clock") => {
                        if args.len() > 1 && args[1] == "set" {   
                            if let Some(clock) = clock {
    
                                let input = args[1..].join(" ");
                
                                match parse_clock_set_input(&input) {
                                    Ok((time, day, month, year)) => {
                            
                                        handle_clock_set(time, day, month, year, clock);
                                        Ok(())
                                    }
                                    Err(err) => Err(err), 
                                }
                            } else {
                                Err("Clock functionality is unavailable.".to_string())
                            }
                        } else {
                            Err("Correct Usage of 'do clock set' command is 'clock set <hh:mm:ss> <day> <month> <year>'.".into())
                        }
                    },
                    Some(&"debug") => {
                        if args.len() == 2 && args[1] == "all" {
                            println!("This may severely impact network performance. Continue? (yes/[no]):");
            
                            let mut save_input = String::new();
                            std::io::stdin().read_line(&mut save_input).expect("Failed to read input");
                            let save_input = save_input.trim();
                    
                            if ["yes", "y", ""].contains(&save_input.to_ascii_lowercase().as_str()) {
                                println!("All possible debugging has been turned on");
                                //Execution must be provided
                                Ok(())
                            } else if ["no", "n"].contains(&save_input.to_ascii_lowercase().as_str()){
                                println!("Returned");
                                //Execution must be provided
                                Ok(())
                            } else {
                                return Err("Invalid input. Please enter 'yes' or 'no'.".into());
                            }
                        } else {
                            Err("Invalid arguments provided to 'do debug all'. This command does not accept additional arguments.".into())
                        }
        
                    },
                    Some(&"undebug") => {
                        if args.len() == 2 && args[1] == "all" {
                            println!("All possible debugging has been turned off");
                            Ok(())
                        } else {
                            Err("Invalid arguments provided to 'do undebug all'. This command does not accept additional arguments.".into())
                        }
        
                    },
                    Some(&"clear") => {
                        if args.len() == 3 && args[1] == "ntp" && args[2] == "associations" {
                            context.ntp_associations.clear();
                            // Reinitialize associations for configured servers
                            println!("NTP associations cleared and reinitialized.");
                            Ok(())
                        } else {
                            Err("Invalid arguments provided to 'do clear ntp associations'. This command does not accept additional arguments.".into())
                        }
        
                    },
                    Some(cmd) => {
                        println!("Invalid do command: {}", cmd);
                        Ok(())
                    },
                    None => {
                        println!("Missing parameter. Usage: do <command>");
                        Ok(())
                    }
                }
            },
        },
    );

    //-------------------------------------------------------------------------------------------------------------------------------
    
    //Save the current configuration
    commands.insert(
        "write",
        Command {
            name: "write memory",
            description: "Save the running configuration to the startup configuration",
            suggestions: Some(vec!["memory"]),
            suggestions1: Some(vec!["memory"]),
            suggestions2: None,
            options: None,
            execute: |args, context, _| {
                if matches!(context.current_mode, Mode::UserMode | Mode::PrivilegedMode | Mode::ConfigMode) {
                    if args.len() == 1 && args[0] == "memory" {
                        save_running_to_startup(context);
                        Ok(())
                    
                    } else {
                        Err("Invalid arguments provided to 'write memory'. This command does not accept additional arguments.".into())
                    }
                } else {
                    Err("The 'write memory' command is only available in EXEC modes and Global configuration mode.".into())
                }
            },
        },
    );
    
    //Save the current configuration 
    commands.insert(
        "copy",
        Command {
            name: "copy",
            description: "Copy running configuration",
            suggestions: Some(vec!["running-config"]),
            suggestions1: Some(vec!["running-config"]),
            suggestions2: Some(vec!["startup-config"]),
            options: Some(vec!["<file_name>     - Enter the file name or 'startup-config'",
            "startup-config"]),
            execute: |args, context, _| {
                if !matches!(context.current_mode, Mode::PrivilegedMode) {
                    return Err("The 'copy' command is only available in Privileged EXEC mode".into());
                }

                if args.len() < 2 || args[0] != "running-config" {
                    println!("Usage: copy running-config startup-config|<file-name>");
                    return Ok(());
                }
                
                let running_config = get_running_config(context);
                let destination = &args[1];
                
                copy_run_config(&running_config, destination, context)
            },
        },
    );

    //Provide help
    commands.insert(
        "help",
        Command {
            name: "help",
            description: "Display available commands for current mode",
            suggestions: None,
            suggestions1: None,
            suggestions2: None,
            options: None,
            execute: |_args, context, _| {
                help_command(&context);
                Ok(())
            }
        },
    );
    
    //Define clock settings
    commands.insert(
        "clock",
        Command {
            name: "clock set",
            description: "Change the clock date and time",
            suggestions: Some(vec!["set"]),
            suggestions1: Some(vec!["set"]),
            suggestions2: None,
            options: Some(vec!["<hh:mm:ss>   - Enter the time in this specified format",
                "<day>      - Enter the day '1-31'",
                "<month>    - Enter a valid month",
                "<year>     - Enter the year"]),
            execute: |args, context, clock| {
                if matches!(context.current_mode, Mode::PrivilegedMode) {
                    if args.len() > 1 && args[0] == "set" {   
                        if let Some(clock) = clock {

                            let input = args.join(" ");
            
                            match parse_clock_set_input(&input) {
                                Ok((time, day, month, year)) => {
                        
                                    handle_clock_set(time, day, month, year, clock);
                                    Ok(())
                                }
                                Err(err) => Err(err), 
                            }
                        } else {
                            Err("Clock functionality is unavailable.".to_string())
                        }
                    } else {
                        Err("Correct Usage of 'clock set' command is 'clock set <hh:mm:ss> <day> <month> <year>'.".into())
                    }
                }
                else {
                    Err("The 'clock set' command is only available in Privileged EXEC mode.".into())
                }
            },
        },
    );
    
    //Assign IP addresses for interfaces and define IP routes
    commands.insert(
        "ip",
        Command {
            name: "ip",
            description: "Define all the ip commands",
            suggestions: Some(vec!["address", "route"]),
            suggestions1: Some(vec!["address", "route"]),
            suggestions2: None,
            options: Some(vec![
                "<IP_Address>   - Enter the IP Address"                
            ]),
            execute: |args, context, _| {
                if args.is_empty() {
                    return Err("Incomplete command. Use 'ip address <IP address> <subnet_mask>' or 'ip route <ip_address> <netmask> <exit_interface> <next_hop>'".into());
                }
    
                match args[0] {
                    "address" => {
                        if args.len() == 1 {
                            println!("Interface details");
                            execute_spawn_process("ip", &["a"])?;
                            return Ok(());
                        } 
                        
                        if args.len() != 3 {
                            return Err("Invalid command format. Use: 'ip address <IP address> <subnet_mask>'".into());
                        }
    
                        if !matches!(context.current_mode, Mode::InterfaceMode) {
                            return Err("The 'ip address' command is only available in Interface Configuration mode.".into());
                        }
    
                        let ip_address = &args[1];
                        let subnet_mask = &args[2];
                        let selected_interface = SELECTED_INTERFACE.lock().unwrap();
                        
                        if selected_interface.is_none() {
                            return Err("No interface selected. Use the 'interface' command first.".into());
                        }
    
                        let interface = selected_interface.as_ref().unwrap();
                        
                        // Configure IP address
                        let cidr_result = ip_with_cidr(ip_address, subnet_mask)?;
                        
                        // Apply configuration to the interface
                        execute_spawn_process("sudo", &["ifconfig", interface, ip_address, "netmask", subnet_mask, "up"])?;
    
                        // Update the IP address state table
                        let mut ip_address_state = IP_ADDRESS_STATE.lock().unwrap();
                        if let Some((existing_ip, existing_broadcast)) = ip_address_state.get_mut(interface) {
                            *existing_ip = ip_address.parse::<Ipv4Addr>().expect("Invalid IP format");
                            *existing_broadcast = subnet_mask.parse::<Ipv4Addr>().expect("Invalid subnet format");
                            println!(
                                "Updated interface {} with IP {} and netmask {}",
                                interface, ip_address, subnet_mask
                            );
                        } else {
                            ip_address_state.insert(interface.clone(), (
                                ip_address.parse::<Ipv4Addr>().expect("Invalid IP format"),
                                subnet_mask.parse::<Ipv4Addr>().expect("Invalid subnet format")
                            ));
                            println!(
                                "Assigned IP {} and netmask {} to interface {}",
                                ip_address, subnet_mask, interface
                            );
                        }
    
                        println!("IP address {} is configured to the interface {}", &cidr_result, interface);
                        Ok(())
                    },
                    "route" => {
                        if !matches!(context.current_mode, Mode::ConfigMode) {
                            return Err("The 'ip route' command is only available in Global Configuration mode.".into());
                        }
                        
                        if args.len() < 5 {
                            return Err("Usage: ip route <ip_address> <netmask> <exit_interface> <next_hop>".into());
                        }
                        
                        let ip_addr = &args[1];
                        let netmask = &args[2];
                        let exit_int = &args[3];
                        let nxt_hop = &args[4];
    
                        // Generate CIDR notation
                        let cidr_notation = ip_with_cidr(ip_addr, netmask)?;
    
                        // Validate interface
                        let (interface_list, interfaces_list) = get_available_int()?;
                        if !interface_list.iter().any(|i| i == exit_int) {
                            return Err(format!("Invalid exit interface: {}. Available interfaces: {}", exit_int, interfaces_list));
                        }
                        
                        // Add route to system
                        println!("Adding route to {} via {} on interface {}", &cidr_notation, nxt_hop, exit_int);
                        execute_spawn_process("sudo", &["ip", "route", "add", &cidr_notation, "via", nxt_hop, "dev", exit_int])?;
                        
                        // Update route table
                        let mut route_table = ROUTE_TABLE.lock().unwrap();
                        route_table.insert(ip_addr.to_string(), (
                            netmask.parse::<Ipv4Addr>().expect("Invalid subnet format"),
                            format!("{} {}", exit_int, nxt_hop)
                        ));
                        
                        println!("Route added successfully");
                        Ok(())
                    },
                    _ => Err("Invalid command format. Use: 'ip address <IP address> <subnet_mask>' or 'ip route <ip_address> <netmask> <exit_interface> <next_hop>'".into())
                }
            },
        }
    );

    //Shutdown interfaces
    commands.insert(
        "shutdown",
        Command {
            name: "shutdown",
            description: "Disable the selected network interface.",
            suggestions: None,
            suggestions1: None,
            suggestions2: None,
            options: None,
            execute: |_, context, _| {
                if matches!(context.current_mode, Mode::InterfaceMode) {
                    let selected_interface = SELECTED_INTERFACE.lock().unwrap();
                    if let Some(ref interface) = *selected_interface {
                        execute_spawn_process("sudo", &["ip", "link", "set", interface, "down"])?;
                        println!("interface {} is set to down", interface);
                        Ok(())
                    } else {
                        Err("No interface selected. Use the 'interface' command first.".into())
                    }
                } else {
                    Err("The 'shutdown' command is only available in Interface Configuration mode.".into())
                }
            },
        },
    );
    
    //enable interfaces, disable ip addresses and disable routes 
    commands.insert(
        "no",
        Command {
            name: "no",
            description: "Enable the selected network interface.",
            suggestions: Some(vec!["shutdown", "ntp", "ip"]),
            suggestions1: Some(vec!["shutdown", "ntp", "ip"]),
            suggestions2: Some(vec!["server", "route"]),
            options: None,
            execute: |args, context, _| {
                if args.len() == 1 && args[0] == "shutdown" {
                    if matches!(context.current_mode, Mode::InterfaceMode) {
                        let selected_interface = SELECTED_INTERFACE.lock().unwrap();
                        if let Some(ref interface) = *selected_interface {
                            execute_spawn_process("sudo", &["ip", "link", "set", interface, "up"])?;
                            execute_spawn_process("sudo", &["netplan", "apply"])?;
                            println!("interface {} is set to up", interface);
                            Ok(())
                        } else {
                            Err("No interface selected. Use the 'interface' command first.".into())
                        }
                    } else {
                        Err("The 'shutdown' command is only available in Interface Configuration mode.".into())
                    }
                } else if args.len() == 3 && args[0] == "ntp" && args[1] == "server" {
                    if matches!(context.current_mode, Mode::ConfigMode) {
                        let ip_address = args[2].to_string();
                        if context.ntp_servers.remove(&ip_address) {
                            // Remove from the associations list as well
                            context.ntp_associations.retain(|assoc| assoc.address != ip_address);
                            println!("NTP server {} removed.", ip_address);
                            Ok(())
                        } else {
                            Err("NTP server not found.".into())
                        }
                    } else {
                        Err("The 'no ntp server' command is only available in configuration mode.".into())
                    }
                } else if args[0] == "ip" && args[1] == "route"{
                    if matches!(context.current_mode, Mode::ConfigMode) {

                        if args.len() < 6 {
                            return Err("Usage: no ip route <ip_address> <netmask> <exit_interface> <next_hop>".into());
                        }

                        let ip_addr = &args[2];
                        let netmask = &args[3];
                        let exit_int = &args[4];
                        let nxt_hop = &args[5];

                        let cidr_notation = match ip_with_cidr(ip_addr, netmask) {
                            Ok(result) => result,
                            Err(e) => return Err(format!("Failed to restructure the IP address: {}", e))
                        };

                        let (interface_list, interfaces_list) = match get_available_int() {
                            Ok(result) => result,
                            Err(e) => return Err(e),
                        };

                        if !interface_list.iter().any(|i| i == exit_int) {
                            return Err(format!("Invalid exit interface: {}. Available interfaces: {}", exit_int, interfaces_list));
                        }
                        
                        println!("Deleting route to {} via {} on interface {}", &cidr_notation, nxt_hop, exit_int);

                        match execute_spawn_process("sudo", &["ip", "route", "del", &cidr_notation, "via", nxt_hop, "dev", exit_int]) {
                            Ok(_) => {
                                println!("Route deleted successfully");
                                return Ok(());
                            },
                            Err(e) => Err::<(), String>(format!("Failed to delete route: {}", e).to_string()),
                        }
                    } else {
                        Err("The 'no ip route' command is only available in configuration mode.".into())
                    }
                } else if args[0] == "ip" && args[1] == "address"{
                    if matches!(context.current_mode, Mode::InterfaceMode) {
                        let ip_address = &args[2];
                        let subnet_mask = &args[3];
                        let selected_interface = SELECTED_INTERFACE.lock().unwrap();
                        if let Some(ref interface) = *selected_interface {
                            match ip_with_cidr(ip_address, subnet_mask) {
                                Ok(result) => {
                                    // Fixed: Use Ok() and ? to handle the Result returned by execute_spawn_process
                                    //println!("IP_address = {}, Interface = {}", &result, interface);
                                    execute_spawn_process("sudo", &["ip", "addr", "del", &result, "dev", interface])?;
                                    println!("IP address {} is removed from the interface {}", &result, interface);
                                    return Ok(());
                                }, 
                                Err(e) => return Err(format!("Failed to remove the IP address: {}", e))
                            }
                        } else {
                            return Err("No interface selected. Use the 'interface' command first.".into());
                        }
                    } else {
                        Err("The 'no ip address' command is only available in Interface Configuration mode.".into())
                    }
                    
                } 
                
                else {
                    Err("Invalid arguments provided to 'no'.".into())
                }
                
            },
        },
    );

    //Clear the terminal
    commands.insert("clear", Command {
        name: "clear",
        description: "Clear processes",
        suggestions: Some(vec!["ntp associations"]),
        suggestions1: None,
        suggestions2: None,
        options: None,
        execute: |args, context, _| {
            match args.get(0) {
                None => {
                    ProcessCommand::new("clear")
                        .status()
                        .unwrap();
                    Ok(())
                },
                Some(&"ntp") => {
                    if !matches!(context.current_mode, Mode::PrivilegedMode) {
                        return Err("The 'clear ntp associations' command is only available in privileged EXEC mode.".into());
                    }
    
                    match args.get(1) {
                        Some(&"associations") => {
                            context.ntp_associations.clear();
                            // Reinitialize associations for configured servers
                            println!("NTP associations cleared and reinitialized.");
                            Ok(())
                        },
                        _ => Err("Invalid command. Usage: clear ntp associations".into())
                    }
                },
                _ => Err("Invalid command. Available commands: clear, clear ntp associations".into())
            }
        },
    });

    //ntp commands
    commands.insert("ntp", Command {
        name: "ntp",
        description: "NTP configuration commands",
        suggestions: Some(vec!["source", "server", "master", "authenticate", "authentication-key", "trusted-key"]),
        suggestions1: Some(vec!["source", "server", "master", "authenticate", "authentication-key", "trusted-key"]),
        suggestions2: None,
        options: None,
        execute: |args, context, _| {
            if !matches!(context.current_mode, Mode::ConfigMode) {
                return Err("NTP commands are only available in configuration mode.".into());
            }
    
            if args.is_empty() {
                return Err("Subcommand required. Available subcommands: server, master, authenticate, authentication-key, trusted-key".into());
            }
    
            match &args[0][..] {
                "server" => {
                    if args.len() == 2 {
                        let ip_address = args[1].to_string();
                        if ip_address.parse::<Ipv4Addr>().is_ok() {
                            context.ntp_servers.insert(ip_address.clone());
                            // Assuming once the server is configured, we add it to NTP associations
                            let association = NtpAssociation {
                                address: ip_address.clone(),
                                ref_clock: ".INIT.".to_string(),
                                st: 16,
                                when: "-".to_string(),
                                poll: 64,
                                reach: 0,
                                delay: 0.0,
                                offset: 0.0,
                                disp: 0.01,
                            };
                            context.ntp_associations.push(association); 
                            println!("NTP server {} configured.", ip_address);
                            Ok(())
                        } else {
                            Err("Invalid IP address format.".into())
                        }
                    } else {
                        Err("Invalid arguments. Usage: ntp server {ip-address}".into())
                    }
                },
                "source" => {
                    if args.len() >= 2 {
                        if args.len() == 2 {
                            let interface_name = args[1].to_string();
                            context.ntp_source_interface = Some(interface_name.clone());
                            println!("NTP source interface set to {}", interface_name);
                            Ok(())
                        } else {
                            Err("Invalid arguments. Usage: ntp source interface {interface-name}".into())
                        }
                    } else {
                        Err("Invalid arguments. Usage: ntp source interface {interface-name}".into())
                    }
                },
                "master" => {
                    context.ntp_master = true;
                    println!("Device configured as NTP master.");
                    Ok(())
                },
                "authenticate" => {
                    if args.len() == 1 {
                        context.ntp_authentication_enabled = !context.ntp_authentication_enabled;
                        let status = if context.ntp_authentication_enabled {
                            "enabled"
                        } else {
                            "disabled"
                        };
                        println!("NTP authentication {}", status);
                        Ok(())
                    } else {
                        Err("Invalid arguments. Use 'ntp authenticate'.".into())
                    }
                },
                "authentication-key" => {
                    if args.len() == 4 && args[2] == "md5" {
                        if let Ok(key_number) = args[1].parse::<u32>() {
                            let md5_key = args[3].to_string();
                            context.ntp_authentication_keys.insert(key_number, md5_key.clone());
                            println!("NTP authentication key {} configured with MD5 key: {}", key_number, md5_key);
                            Ok(())
                        } else {
                            Err("Invalid key number. Must be a positive integer.".into())
                        }
                    } else {
                        Err("Invalid arguments. Use 'ntp authentication-key <key-number> md5 <key-value>'.".into())
                    }
                },
                "trusted-key" => {
                    if args.len() == 2 {
                        if let Ok(key_number) = args[1].parse::<u32>() {
                            context.ntp_trusted_keys.insert(key_number);
                            println!("NTP trusted key {} configured.", key_number);
                            Ok(())
                        } else {
                            Err("Invalid key number. Must be a positive integer.".into())
                        }
                    } else {
                        Err("Invalid arguments. Use 'ntp trusted-key <key-number>'.".into())
                    }
                },
                _ => Err("Invalid NTP subcommand. Available subcommands: server, master, authenticate, authentication-key, trusted-key".into())
            }
        }
    });
  
    //Encrypt the passwords
    commands.insert("service", Command {
        name: "service password-encryption",
        description: "Enable password encryption",
        suggestions: Some(vec!["password-encryption"]),
        suggestions1: Some(vec!["password-encryption"]),
        suggestions2: None,
        options: None,
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::ConfigMode) {
                if args.len() == 1 && args[0] == "password-encryption" {
                    let storage = PASSWORD_STORAGE.lock().unwrap();
                    
                    let stored_password = storage.enable_password.clone();
                    let stored_secret = storage.enable_secret.clone();
                    drop(storage);
                    
                    if let Some(password) = stored_password {
                        let encrypted_password = encrypt_password(&password);
                        context.config.encrypted_password = Some(encrypted_password);
                    }
                    
                    if let Some(secret) = stored_secret {
                        let encrypted_secret = encrypt_password(&secret);
                        context.config.encrypted_secret = Some(encrypted_secret);  // Update encrypted secret
                    }
        
                    context.config.password_encryption = true;
                    println!("Password encryption enabled.");
                    Ok(())
                } else {
                    Err("Invalid arguments provided to 'service password-encryption'. This command does not accept additional arguments.".into())
                }
            } else {
                Err("The 'service password-encryption' command is only available in Privileged EXEC mode.".into())
            }
        },
    });

    //Connect via SSH
    commands.insert(
        "ssh",
        Command {
            name: "ssh",
            description: "Establish SSH connection to a remote host",
            suggestions: Some(vec![
                "-v",
                "-l",
                "-h",
                "--help"
            ]),
            suggestions1: Some(vec![
                "-v",
                "-l",
                "-h",
                "--help"
            ]),
            suggestions2: None,
            options: None,
            execute: |args, context, _| {
                    match args.get(0) {
                        Some(&"-v") => {
                            if args.len() == 1 {
                                println!("OpenSSH_8.9p1 Ubuntu-3ubuntu0.1, OpenSSL 3.0.2 15 Mar 2022");
                                return Ok(());
                            } else if args.len() > 1 {
                                let version_str = &args[1];
                                if let Ok(version) = version_str.parse::<u32>() {
                                    if version < 10 {
                                        println!("Changed to SSH version {}", version);
                                    } else {
                                        println!("Invalid version. Please enter a valid version");
                                    }
                                } else {
                                    println!("Invalid version input: {}", version_str);
                                }
                                return Ok(());
                            } else{
                                println!("Invalid usage. ssh -v [version]");
                                Ok(())
                            }
                        },
                        Some(&"-l") => {
                            if args.len() < 2 {
                                println!("Usage: ssh -l <username>@<ip-address>");
                                return Ok(());
                            }
    
                            let connection_string = args[1];
                            
                            // Split the connection string into username and ip
                            match connection_string.split_once('@') {
                                Some((username, ip)) => {
                                    connect_via_ssh(username, ip)?; 
                                    println!("Connected successfully!");
                                    Ok(())
                                },
                                None => {
                                    println!("Invalid format. Use: ssh -l username@ip-address");
                                    println!("Example: ssh -l admin@192.168.1.1");
                                    Ok(())
                                }
                            }
                        },
                        Some(&help) if help == "-h" || help == "--help" => {
                            println!("SSH Command Usage:");
                            println!("  ssh -v                     Display SSH version");
                            println!("  ssh -l username@ip-address Login to remote server");
                            println!("\nExamples:");
                            println!("  ssh -l admin@192.168.1.1");
                            Ok(())
                        },
                        Some(cmd) => {
                            println!("Invalid SSH option: {}", cmd);
                            println!("Use 'ssh -h' for help");
                            Ok(())
                        },
                        None => {
                            println!("Missing parameters. Use 'ssh -h' for help");
                            Ok(())
                        }
                    }
                
            },
        }
    );

    commands.insert("dhcp_enable", Command { 
        name: "enable dhcp", 
        description: "Enabling dhcp for network connectivity", 
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: None, 
        execute: |args, _context, _| {
           
            execute_spawn_process("sudo", &["dhclient", "-r"]); 
            println!("Removed existing dhcp configurations");
            execute_spawn_process("sudo", &["dhclient"]); 
            println!("Enabled dhcp configurations");
            execute_spawn_process("sudo", &["systemctl", "restart", "NetworkManager"]); 
            println!("Restart Network services");
            Ok(())

        },
    });


    //ping command
    commands.insert("ping", Command {
        name: "ping",
        description: "Ping a specific IP address to check reachability",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: Some(vec!["<ip-address>    - Enter the ip-address"]),
        execute: |args, _context, _| {
            if args.len() == 1 {
                let ip = args[0].to_string();
                
                println!("Pinging {} with 32 bytes of data:", ip);
                
                execute_spawn_process("ping", &["-c", "4", "-s", "32", &ip]);
                Ok(())

            } else {
                Err("Invalid syntax. Usage: ping <ip>".into())
            }
        },
    });
    
    //traceroute command
    commands.insert("traceroute", Command {
        name: "traceroute",
        description: "Trace the route to a specific IP address or hostname",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: Some(vec!["<ip-address/hostname>    - Enter the IP address or hostname"]),
        execute: |args, _context, _| {
            if args.len() == 1 {
                let target = args[0].to_string();
    
                println!("Tracing route to {} over a maximum of 30 hops", target);
    
                execute_spawn_process("traceroute", &["-n", "-m", "30", &target]);
                println!("Trace Completed.");
                Ok(())

            } else {
                Err("Invalid syntax. Usage: traceroute <ip/hostname>".into())
            }
        },
    });

    //--------------------------------------------------------------------------------------------------------------------------------
    //Software and Database Management Mode Commands
    
    //Stores the FW version
    commands.insert("Transfer_sw", Command {
        name: "Transfer_sw",
        description: "Stores a specific firmware version",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: Some(vec!["<firmware_x>    - Enter the firmware path", 
        "<device_x>     - Enter the device (NP, SEM, Chassis_M)",
        "<slot_x>       - Define the memory slot"]),
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::SDMMode) {
                if args.len() == 3 {
                    let firmware_path = "/home/uthpala/Documents/CLI_IMP_Extra_Commands";     //Define the specific path
                    let firmware = format!("{}/{}", firmware_path, args[0]);
                    let device_name = &args[1];
                    let m_slot = &args[2];
                    let dest_path = format!("{}/{}", device_name, m_slot);
                    //connect to the specific device
                    //execute_spawn_process("sudo", &["cp", &firmware, &dest_path]);
                    println!("Stored the {} firmware version on {}", firmware, dest_path);
                    Ok(())
                } else {
                    Err("The command is 'Transfer_sw <firmware_x> <device_x> <slot_x>'".into())
                }
            } else {
                Err("The 'Trasnfer_sw' command is only available in Software and Database Management Mode.".into())
            }
        },
    });

    //Updates the FW version
    commands.insert("Update", Command {
        name: "Update",
        description: "Installs the specified firmware version (firmware_x) onto the requested target",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: Some(vec!["<firmware_x>    - Enter the firmware path", 
        "<target>     - Enter the device/target"]),
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::SDMMode) {
                if args.len() == 2 {
                    let firmware_path = "/home/uthpala/Documents/CLI_IMP_Extra_Commands";     //Define the specific path
                    let firmware = format!("{}/{}", firmware_path, args[0]);
                    let target = &args[1];
                    //connect to the specific device
                    //execute_spawn_process("sudo", &["fwupdmgr", &firmware, &target]);
                    println!("Updated the {} firmware version on {}", firmware, target);
                    Ok(())
                } else {
                    Err("The command is 'Update <firmware_x> <target>'".into())
                }
            } else {
                Err("The 'Update' command is only available in Software and Database Management Mode.".into())
            }
        },
    });

    //Reverse FW updates
    commands.insert("Rollback", Command {
        name: "Rollback",
        description: "Rolls back the device (device_x) to the requested firmware version (version)",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: Some(vec!["<device_x>    - Enter the target device", 
        "<version>     - Enter the firmware version"]),
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::SDMMode) {
                if args.len() == 2 {
                    let firmware_path = "/home/uthpala/Documents/CLI_IMP_Extra_Commands";     //Define the specific path
                    let firmware_version = &args[1];
                    let firmware = format!("{}/*/{}", firmware_path, firmware_version);
                    let device = &args[0];
                    //connect to the specific device
                    //execute_spawn_process("sudo", &["fwupdmgr", &firmware, &device]);
                    println!("Rolled back to the {} firmware version on {}", firmware, device);
                    Ok(())
                } else {
                    Err("The command is 'Rollback <device_x> <version>'".into())
                }
            } else {
                Err("The 'Rollback' command is only available in Software and Database Management Mode.".into())
            }
        },
    });

    //Get the versions of FW
    commands.insert("Get_version", Command {
        name: "Get_version",
        description: "Retrieves the firmware version for the specified target device (device_x)",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: Some(vec!["<device_x>    - Enter the target device", 
        "<option>     - Option can be either running or stored"]),
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::SDMMode) {
                if args.len() == 2 {
                    let firmware_path = "/home/uthpala/Documents/CLI_IMP_Extra_Commands";     //Define the specific path
                    let option = &args[1];
                    let device = &args[0];
                    //connect to the specific device
                    if args[1] =="running" {
                        //execute_spawn_process("sudo", &["fwupdmgr", "--version"]);
                        //Get the FWs present from the terminal
                        let version = "FW.123";
                        println!("The current running Firmware version for {} is {}", device, version);
                        Ok(())
                    } else if args[1] == "stored" {
                        //execute_spawn_process("sudo", &["fwupdmgr", "get-updates"]);
                        let versions = "FW.123, FW.122, FW.121";
                        println!("The stored firmware versions for {} are: {}", device, versions);
                        Ok(())
                    } else {
                        Err("Invalid option. The command is 'Get_version <device_x> [running|stored]".into())
                    }
                } else {
                    Err("The command is 'Get_version <device_x> [running|stored]'".into())
                }
            } else {
                Err("The 'Get_version' command is only available in Software and Database Management Mode.".into())
            }
        },
    });

    //Get all possible firmware updates
    commands.insert("Get_all_versions", Command {
        name: "Get_all_versions",
        description: "Returns detailed information about all stored firmware versions to the requester (local or remote).",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: None,
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::SDMMode) {
                //execute_spawn_process("sudo", &["fwupdmgr", "get-devices"]);
                let versions = "FW.123, FW.122, FW.121";
                println!("The stored firmware versions are: {}", versions);
                Ok(())
            } else {
                Err("The 'Get_all_versions' command is only available in Software and Database Management Mode.".into())
            }
        },
    });

    //--------------------------------------------------------------------------------------------------------------------------------
    //Built-in Testing and Diagnostic Mode Commands

    //Initiation of 'Initiated Built-In Test'
    commands.insert("Initiate", Command {
        name: "Initiate ibit",
        description: "Initiates the Initiated Built-In Test (IBIT) upon request from the Remote Manager",
        suggestions: Some(vec!["ibit"]),
        suggestions1: Some(vec!["ibit"]),
        suggestions2: None,
        options: None,
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::BITDMode) {
                if args.len() == 1 && args[0] =="ibit" {
                    println!("Initiated the Initiated Built-In Test (IBIT)");
                    Ok(())
                } else {
                    Err("The command is 'initiate ibit'".into())
                }
            } else {
                Err("The 'Initiate' command is only available in Built-in Testing and Diagnostic Mode.".into())
            }
        },
    });

    //Get logs from the Built-In tests
    commands.insert("Get_logs", Command {
        name: "Get-Logs",
        description: "Retrieves logs from Built-In Tests (BIT), including SBIT, CBIT, or IBIT.",
        suggestions: Some(vec!["ibit", "sbit", "cbit"]),
        suggestions1: Some(vec!["ibit", "sbit", "cbit"]),
        suggestions2: None,
        options: None,
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::BITDMode) {
                if args.len() == 1 {
                    if args[0] == "sbit" {
                        //execute_spawn_process("journalctl", &["-b", "-p", "err"]);
                        //execute_spawn_process("systemctl", &["--failed"]);
                        //execute_spawn_process("journalctl", &["--boot=-1"]);
                        println!("Getting logs from Startup Built-In Test (IBIT)");
                        Ok(())
                    } else if args[0] == "cbit" {
                        //execute_spawn_process("dmesg", &["-w"]);
                        //execute_spawn_process("journalctl", &["-k", "|", "grep", "-i", "error"]);
                        println!("Getting logs from Continuous Built-In Test (IBIT)");
                        Ok(())
                    } else if args[0] == "ibit" {
                        //execute_spawn_process("systemd-analyze", &["blame"]);
                        //execute_spawn_process("systemd-analyze", &["critical-chain"]);
                        //execute_spawn_process("lshw", &["-short"]);
                        println!("Getting logs from Initiated Built-In Test (IBIT)");
                        Ok(())
                    } else {
                        Err("Invalid bit declaration {ibit, sbit, cbit}. The command is 'Get_logs <bit>'".into())
                    }
                } else {
                    Err("The command is 'Get_logs <bit>'".into())
                }
            } else {
                Err("The 'Get_logs' command is only available in Built-in Testing and Diagnostic Mode.".into())
            }
        },
    });

    //Get the status of Startup Built-In Testing and Diagnostics
    commands.insert("Get_status", Command {
        name: "Get_status ",
        description: "Retrieves the current status of a specified BIT test (running, completed, failed, etc.).",
        suggestions: Some(vec!["ibit", "sbit", "cbit"]),
        suggestions1: Some(vec!["ibit", "sbit", "cbit"]),
        suggestions2: None,
        options: None,
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::BITDMode) {
                if args.len() == 1 {
                    if args[0] == "sbit" {
                        //execute_spawn_process("systemctl", &["status", "systemd-fsck-root"]);
                        println!("Getting status from Startup Built-In Test (IBIT)");
                        Ok(())
                    } else if args[0] == "cbit" {
                        //execute_spawn_process("dmesg", &["-w"]);
                        println!("Getting status from Continuous Built-In Test (IBIT)");
                        Ok(())
                    } else if args[0] == "ibit" {
                        //execute_spawn_process("systemd-analyze", &["blame"]);
                        //execute_spawn_process("systemd-analyze", &["critical-chain"]);
                        println!("Getting status from Initiated Built-In Test (IBIT)");
                        Ok(())
                    } else {
                        Err("Invalid bit declaration {ibit, sbit, cbit}. The command is 'Get_status <bit>'".into())
                    }
                } else {
                    Err("The command is 'Get_status <bit>'".into())
                }
            } else {
                Err("The 'Get_status' command is only available in Built-in Testing and Diagnostic Mode.".into())
            }
        },
    });

    //Clear logs of Startup Built-In Testing and Diagnostics
    commands.insert("Clear_logs", Command {
        name: "Clear logs ",
        description: "Clears logs of a specific BIT test to free up memory or reset error tracking.",
        suggestions: Some(vec!["ibit", "sbit", "cbit"]),
        suggestions1: Some(vec!["ibit", "sbit", "cbit"]),
        suggestions2: None,
        options: None,
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::BITDMode) {
                if args.len() == 1 {
                    if args[0] == "sbit" {
                        //execute_spawn_process("journalctl", &["--vacuum-time=100M"]);
                        println!("Getting status from Startup Built-In Test (IBIT)");
                        Ok(())
                    } else if args[0] == "cbit" {
                        //execute_spawn_process("dmesg", &["--clear"]);
                        //execute_spawn_process("systemctl", &["restart", "rsyslog"]);
                        println!("Getting status from Continuous Built-In Test (IBIT)");
                        Ok(())
                    } else if args[0] == "ibit" {
                        //execute_spawn_process("journalctl", &["-u", "ibittest.service", "--rotate"]);
                        println!("Getting status from Initiated Built-In Test (IBIT)");
                        Ok(())
                    } else {
                        Err("Invalid bit declaration {ibit, sbit, cbit}. The command is 'Clear_logs <bit>'".into())
                    }
                } else {
                    Err("The command is 'Clear_logs <bit>'".into())
                }
            } else {
                Err("The 'Clear_logs' command is only available in Built-in Testing and Diagnostic Mode.".into())
            }
        },
    });

    //Set the threshold for the 'Continuos Built-In Test'
    commands.insert("Set_threshold", Command {
        name: "Set Threshold",
        description: "Configures a threshold (e.g., temperature, latency, error count) for CBIT monitoring.",
        suggestions: Some(vec!["cbit"]),
        suggestions1: Some(vec!["cbit"]),
        suggestions2: None,
        options: Some(vec!["<Temp-limit>        - Set the temperature limit"]),
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::BITDMode) {
                if args.len() == 2 && args[0] =="cbit" {
                    let value = &args[1];
                    //execute_spawn_process("sudo", &["sensors"]); //Get the temp limits
                    println!("The threshold set for the temperature as {}C", value);
                    Ok(())
                } else {
                    Err("The command is 'Set_threshold cbit <value>'".into())
                }
            } else {
                Err("The 'Set_threshold' command is only available in Built-in Testing and Diagnostic Mode.".into())
            }
        },
    });

    //List failures in BITD
    commands.insert("List_failures", Command {
        name: "List_failures",
        description: "Lists recent system failures detected by BITD along with failure codes and timestamps.",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: None,
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::BITDMode) {
                //execute_spawn_process("systemctl", &["--failed"])
                println!("The testing failures are as follows:
                0 loaded units listed.");
                Ok(())
            } else {
                Err("The 'List_failures' command is only available in Built-in Testing and Diagnostic Mode.".into())
            }
        },
    });

    //Get diagnostics for the failure ID specified
    commands.insert("Get_diagnostics", Command {
        name: "Get_diagnostics",
        description: "Retrieves in-depth failure analysis for a specific issue detected by BITD.",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: Some(vec!["<failure-ID>        - Enter the failure ID"]),
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::BITDMode) {
                if args.len() == 1 {
                    let f_id = &args[0];
                    //execute_spawn_process("sudo", &["lshw", "-short", "-c", "memory", "-businfo", "|", "grep", &f_id]); 
                    println!("Diagnostics are taken for the failure ID {}", f_id);
                    Ok(())
                } else {
                    Err("The command is 'Get_diagnostics <failure_id>>'".into())
                }
            } else {
                Err("The 'Get_diagnostics' command is only available in Built-in Testing and Diagnostic Mode.".into())
            }
        },
    });

    //List failures in BITD
    commands.insert("Run_health_check", Command {
        name: "Run_health_check",
        description: "Runs a quick system-wide health check using BITD tests and returns a summary.",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: None,
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::BITDMode) {
                //execute_spawn_process("sudo", &["lshw", "-short"]);  //Basic health check
                //execute_spawn_process("top", &["-n", "1", "|", "head", "-10"]);   //Check CPU load
                //execute_spawn_process("free", &["-h"]);      // Check memory usage
                //execute_spawn_process("dh", &["-h"]);     //chack disk space
                println!("Running the health check...");
                Ok(())
            } else {
                Err("The 'Run_health_check' command is only available in Built-in Testing and Diagnostic Mode.".into())
            }
        },
    });

    //Get diagnostics for the failure ID specified
    commands.insert("Enable_auto_diagnostics", Command {
        name: "Enable_auto_diagnostics",
        description: "Turns automatic failure diagnostics on or off for CBIT failures",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: Some(vec!["<on/off>        - Set the settings on or off"]),
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::BITDMode) {
                if args.len() == 1 && args[0] == "on" {
                    //install smartmontools and mtr
                    //sudo systemctl enable smartd
                    //sudo systemctl start smartd
                    //mtr --report 8.8.8.8
                    //execute_spawn_process("sudo", &[""]); 
                    println!("Automatic failure diagnostics is turned on");
                    Ok(())
                } else if args.len() == 1 && args[0] == "off" {
                    //install smartmontools and remove mtr
                    //sudo systemctl stop smartd
                    //sudo systemctl disable smartd
                    //execute_spawn_process("sudo", &[""]); 
                    println!("Automatic failure diagnostics is turned off");
                    Ok(()) 
                }else {
                    Err("The command is 'Enable_auto_diagnostics [on|off]'".into())
                }
            } else {
                Err("The 'Enable_auto_diagnostics' command is only available in Built-in Testing and Diagnostic Mode.".into())
            }
        },
    });

    //--------------------------------------------------------------------------------------------------------------------------------
    //Position and Time Management Mode Commands

    //Set remote position - only the remote operator has access
    commands.insert("Set_remote_position", Command {
        name: "Set_remote_position",
        description: "Sets the system’s position to the value provided by the Remote Controller. Returns success or failure.",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: Some(vec!["<pos>        - Set the position (25.276987,55.296249)"]),
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::TPMMode) {
                if args.len() == 1  {
                    let position = &args[0];
                    //sudo nano /etc/geoclue/geoclue.conf
                    //[enable-manual] --> enable=true
                    //gdbus call --session --dest org.freedesktop.GeoClue2 --object-path /org/freedesktop/GeoClue2/Client --method org.freedesktop.GeoClue2.Client.SetLocation "37.7749" "-122.4194" "30"
                    //execute_spawn_process("", &[""]); 
                    println!("The remote position is set to {}", position);
                    Ok(())
                }else {
                    Err("The command is 'Set_remote_position <pos>'".into())
                }
            } else {
                Err("The 'Set_remote_position' command is only available in Position and Time management Mode.".into())
            }
        },
    });

    //Set local position - only the local operator has access
    commands.insert("Set_local_position", Command {
        name: "Set_local_position",
        description: "Sets the system’s position to the value provided by the local Controller. Returns success or failure.",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: Some(vec!["<pos>        - Set the position (25.276987,55.296249)"]),
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::TPMMode) {
                if args.len() == 1  {
                    let position = &args[0];
                    //sudo nano /etc/geoclue/geoclue.conf
                    //[enable-manual] --> enable=true
                    //gdbus call --session --dest org.freedesktop.GeoClue2 --object-path /org/freedesktop/GeoClue2/Client --method org.freedesktop.GeoClue2.Client.SetLocation "37.7749" "-122.4194" "30"
                    //execute_spawn_process("", &[""]);
                    println!("The local position is set to {}", position);
                    Ok(())
                }else {
                    Err("The command is 'Set_local_position <pos>'".into())
                }
            } else {
                Err("The 'Set_local_position' command is only available in Position and Time management Mode.".into())
            }
        },
    });

    //Provide the current position
    commands.insert("Provide_position", Command {
        name: "Provide_position",
        description: "Returns the current position data to the requester (Local or Remote).",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: None,
        execute: |_args, context, _| {
            if matches!(context.current_mode, Mode::TPMMode) {
                //curl -s https://ipinfo.io/loc
                //execute_spawn_process("curl", &["-s", "https://ipinfo.io/loc"]); //based on public ip address
                println!("The current position is ...");
                Ok(())
            } else {
                Err("The 'Provide_position' command is only available in Position and Time management Mode.".into())
            }
        },
    });

    //Provide the current time
    commands.insert("Provide_time", Command {
        name: "Provide_time",
        description: "Returns the current time data to the requester (Local or Remote).",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: None,
        execute: |_args, context, clock| {
            if matches!(context.current_mode, Mode::TPMMode) { 
                show_clock(clock);
                Ok(())
            } else {
                Err("The 'Provide_time' command is only available in Position and Time management Mode.".into())
            }
        },
    });

    //Selects the time source
    commands.insert("Select_time_source", Command {
        name: "Select_time_source",
        description: "Selects the time source from one of the following: GNSS, remote, or local.",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: Some(vec!["<option>        - Select the time source (GNSS, remote, local)"]),
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::TPMMode) {
                if args.len() == 1  {
                    let source = &args[0];
                    //execute_spawn_process("sudo", &[""]); 
                    println!("The time source is selscted as {}", source);
                    Ok(())
                }else {
                    Err("The command is 'Select_time_source <options>'".into())
                }
            } else {
                Err("The 'Select_time_source' command is only available in Position and Time management Mode.".into())
            }
        },
    });

    //Get_time_source
    commands.insert("Get_time_source", Command {
        name: "Get_time_source",
        description: "Returns the currently active time source.",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: None,
        execute: |_args, context, _| {
            if matches!(context.current_mode, Mode::TPMMode) {
                //execute_spawn_process("timedatectl", &["status"]); 
                //Extract the currently available one
                println!("The time source is ... ...");
                Ok(())
            } else {
                Err("The 'Get_time_source' command is only available in Position and Time management Mode.".into())
            }
        },
    });

    //Sync time 
    commands.insert("Sync_time_now", Command {
        name: "Sync_time_now",
        description: "Immediately synchronizes the system time with the currently selected time source.",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: None,
        execute: |_args, context, _| {
            if matches!(context.current_mode, Mode::TPMMode) {
                //For NTP --> sudo ntpdate -u <NTP_server>
                //For hwd clock --> sudo hwclock --hctosys
                //For system clock --> sudo hwclock --systohc
                //execute_spawn_process("sudo", &[""]); 
                println!("Syncing time ...");
                Ok(())
            } else {
                Err("The 'Sync_time_now' command is only available in Position and Time management Mode.".into())
            }
        },
    });

    //Getting sysncing time data
    commands.insert("Get_sync_status", Command {
        name: "Get_sync_status",
        description: "Retrieves synchronization status, including drift, last sync time, and accuracy.",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: None,
        execute: |_args, context, _| {
            if matches!(context.current_mode, Mode::TPMMode) {
                //execute_spawn_process("timedatectl", &["status"]); 
                println!("Getting syncing status ...");
                Ok(())
            } else {
                Err("The 'Get_sync_status' command is only available in Position and Time management Mode.".into())
            }
        },
    });

    //Enables holdover
    commands.insert("Enable_holdover", Command {
        name: "Enable_holdover",
        description: "Enables or disables holdover mode, which maintains accurate time when GNSS is lost.",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: Some(vec!["<on|off>        - Mention the status on or off"]),
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::TPMMode) {
                if args.len() == 1 && args[0] == "on" {
                    //execute_spawn_process("sudo", &[""]); 
                    println!("Holdover mode is enabled");
                    Ok(())
                } else if args.len() == 1 && args[0] == "off" {
                    //execute_spawn_process("sudo", &[""]); 
                    println!("Holdover mode is disabled");
                    Ok(()) 
                }else {
                    Err("The command is 'Enable_holdover [on|off]'".into())
                }
            } else {
                Err("The 'Enable_holdover' command is only available in Position and Time management Mode.".into())
            }
        },
    });

    //Getting current holdover status
    commands.insert("Get_holdover_status", Command {
        name: "Get_holdover_status",
        description: "Returns the current holdover status and estimated accuracy.",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: None,
        execute: |_args, context, _| {
            if matches!(context.current_mode, Mode::TPMMode) {
                //execute_spawn_process("sudo", &[""]); 
                println!("Getting holdover status ...");
                Ok(())
            } else {
                Err("The 'Get_holdover_status' command is only available in Position and Time management Mode.".into())
            }
        },
    });

    //Validate the time source
    commands.insert("Validate_time_source", Command {
        name: "Validate_time_source",
        description: "Runs a validation check on a specific time source (GNSS, NTP, RTC) and returns reliability metrics.",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: Some(vec!["<source>        - Select the time source (GNSS, NTP, RTC)"]),
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::TPMMode) {
                if args.len() == 1  {
                    let source = &args[0];
                    // NTP --> ntpq -p
                    //GNSS --> cgps -s
                    //RTC --> sudo hwclock --show
                    //execute_spawn_process("sudo", &[""]); 
                    println!("The time source is selscted as {}", source);
                    Ok(())
                }else {
                    Err("The command is 'Validate_time_source <source>'".into())
                }
            } else {
                Err("The 'Validate_time_source' command is only available in Position and Time management Mode.".into())
            }
        },
    });

    //set the time manually
    commands.insert(
        "Set_manual_time",
        Command {
            name: "Set_manual_time",
            description: "Change the clock date and time",
            suggestions: None,
            suggestions1: None,
            suggestions2: None,
            options: Some(vec!["<YYYY-MM-DD>       - Enter the date in the following format",
            "<hh:mm:ss>      - Enter the time in this specified format"]),
            execute: |args, context, clock| {
                if matches!(context.current_mode, Mode::TPMMode) {
                    if args.len() == 2 {
                        let date = &args[0];
                        let time = &args[1];
                        
                        if !date.contains('-') || date.split('-').count() != 3 {
                            return Err("Invalid date format. Use YYYY-MM-DD format.".into());
                        }
                        
                        if !time.contains(':') || time.split(':').count() != 3 {
                            return Err("Invalid time format. Use hh:mm:ss format.".into());
                        }
                        
                        let datetime = format!("{} {}", date, time);
                        
                        println!("System date and time has been set to: {}", datetime);
                        
                        // Update hardware clock to sync with system time
                        // execute_spawn_process("sudo", &["hwclock", "--systohc"]);
                        Ok(())
                    } else {
                        Err("Correct usage of 'Set_manual_time' command is 'Set_manual_time <YYYY-MM-DD> <hh:mm:ss>'.".into())
                    }
                }
                else {
                    Err("The 'Set_manual_time ' command is only available in Position and Time management mode.".into())
                }
            },
        },
    );

    //Enable security checks
    commands.insert("Enable_security_checks", Command {
        name: "Enable_security_checks",
        description: "Enables or disables authentication and validation checks for time and position data.",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: Some(vec!["<on|off>        - Mention the status on or off"]),
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::TPMMode) {
                if args.len() == 1 && args[0] == "on" {
                    //execute_spawn_process("sudo", &[""]); 
                    println!("Security check is enabled");
                    Ok(())
                } else if args.len() == 1 && args[0] == "off" {
                    //execute_spawn_process("sudo", &[""]); 
                    println!("Security check is disabled");
                    Ok(()) 
                }else {
                    Err("The command is 'Enable_security_checks [on|off]'".into())
                }
            } else {
                Err("The 'Enable_security_checks' command is only available in Position and Time management Mode.".into())
            }
        },
    });

    //Get security status
    commands.insert("Get_security_status", Command {
        name: "Get_security_status",
        description: "Returns the status of integrity checks, including spoofing detection results.",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: None,
        execute: |_args, context, _| {
            if matches!(context.current_mode, Mode::TPMMode) {
                //execute_spawn_process("sudo", &[""]); 
                println!("Getting security status ...");
                Ok(())
            } else {
                Err("The 'Get_security_status' command is only available in Position and Time management Mode.".into())
            }
        },
    });

    //--------------------------------------------------------------------------------------------------------------------------------
    //Radio Transmission Control Mode Commands

    //Turning RF emmissions on and off
    commands.insert("emcon", Command {
        name: "emcon",
        description: "Enables or disables Emission Control (EMCON) mode, turning RF emissions on or off.",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: Some(vec!["<on|off>        - Mention the status on or off"]),
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::RTxCMode) {
                if args.len() == 1 && args[0] == "on" {
                    //sudo gpsctl -x "$PMTK161,0"
                    //execute_spawn_process("sudo", &[""]); 
                    println!("RF Emmissions enabled");
                    Ok(())
                } else if args.len() == 1 && args[0] == "off" {
                    //sudo gpsctl -x "$PMTK161,1"
                    //execute_spawn_process("sudo", &[""]); 
                    println!("RF emmissions disabled");
                    Ok(()) 
                }else {
                    Err("The command is 'emcon [on|off]'".into())
                }
            } else {
                Err("The 'emcon' command is only available in Radio Transmission Control Mode.".into())
            }
        },
    });

    //Defining mode
    commands.insert("rf_mode", Command {
        name: "rf_mode",
        description: "Sets the radio to either Receive-Only Mode (Rx_only) or Full-Duplex Mode (tx_rx).",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: Some(vec!["<rx_only|tx_rx>        - Enter the duplex mode"]),
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::RTxCMode) {
                if args.len() == 1 && args[0] == "rx_only" {
                    //uhd_usrp_probe --args "tx_enable=0"
                    //execute_spawn_process("sudo", &[""]); 
                    println!("Receiver only mode enabled");
                    Ok(())
                } else if args.len() == 1 && args[0] == "tx_rx" {
                    //uhd_usrp_probe --args "tx_enable=1"
                    //execute_spawn_process("sudo", &[""]); 
                    println!("Full duplex mode enabled");
                    Ok(()) 
                }else {
                    Err("The command is 'rf_mode [rx_only|tx_rx]'".into())
                }
            } else {
                Err("The 'rf_mode' command is only available in Radio Transmission Control Mode.".into())
            }
        },
    });

    //Get RF status
    commands.insert("get_rf_status", Command {
        name: "get_rf_status",
        description: "Returns the current RF transmission mode (Rx_only or Tx/Rx) and EMCON status.",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: None,
        execute: |_args, context, _| {
            if matches!(context.current_mode, Mode::RTxCMode) {
                //uhd_usrp_probe | grep "TX"
                //execute_spawn_process("sudo", &[""]); 
                println!("Getting RF status ...");
                Ok(())
            } else {
                Err("The 'get_rf_status' command is only available in Radio Transmission Control Mode.".into())
            }
        },
    });

    //Setting the power level
    commands.insert("set_power_level", Command {
        name: "set_power_level",
        description: "Adjusts the radio transmission power (if applicable). Accepts values based on radio specifications.",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: Some(vec!["<level>        - Enter the radio specification level"]),
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::RTxCMode) {
                if args.len() == 1 {
                    let level = &args[0];
                    //Needs Universal Software Radio Peripheral
                    //uhd_usrp_probe --args="tx_gain=30"
                    //execute_spawn_process("sudo", &[""]); 
                    println!("Power level set to {}%", level);
                    Ok(()) 
                }else {
                    Err("The command is 'set_power_level <level>'".into())
                }
            } else {
                Err("The 'set_power_level' command is only available in Radio Transmission Control Mode.".into())
            }
        },
    });

    //Get power level
    commands.insert("get_power_level", Command {
        name: "get_power_level",
        description: "Retrieves the current transmission power level.",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: None,
        execute: |_args, context, _| {
            if matches!(context.current_mode, Mode::RTxCMode) {
                //Needs Universal Software Radio Peripheral
                //uhd_usrp_probe | grep "TX Gain"
                //execute_spawn_process("sudo", &[""]); 
                println!("Getting power level ...");
                Ok(())
            } else {
                Err("The 'get_power_level' command is only available in Radio Transmission Control Mode.".into())
            }
        },
    });

    //RF configuration locking
    commands.insert("lock_rf_config", Command {
        name: "lock_rf_config",
        description: "Prevents further changes to RF settings until manually unlocked by the remote controller.",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: Some(vec!["<on|off>        - Mention the status on or off"]),
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::RTxCMode) {
                if args.len() == 1 && args[0] == "on" {
                    //uhd_usrp_probe --args="lock=true"
                    //execute_spawn_process("sudo", &[""]); 
                    println!("RF Configuration locked");
                    Ok(())
                } else if args.len() == 1 && args[0] == "off" {
                    //uhd_usrp_probe --args="lock=false"
                    //execute_spawn_process("sudo", &[""]); 
                    println!("RF configuration not locked");
                    Ok(()) 
                }else {
                    Err("The command is 'lock_rf_config [on|off]'".into())
                }
            } else {
                Err("The 'lock_rf_config' command is only available in Radio Transmission Control Mode.".into())
            }
        },
    });

    //unlock RF config
    commands.insert("unlock_rf_config", Command {
        name: "unlock_rf_config",
        description: "Unlocks previously locked RF configuration settings.",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: None,
        execute: |_args, context, _| {
            if matches!(context.current_mode, Mode::RTxCMode) {
                //uhd_usrp_probe --args="lock=false"
                //execute_spawn_process("sudo", &[""]); 
                println!("Unlocking RF configuration ...");
                Ok(())
            } else {
                Err("The 'unlock_rf_config' command is only available in Radio Transmission Control Mode.".into())
            }
        },
    });

    //Force Tx Enable
    commands.insert("force_tx_enable", Command {
        name: "force_tx_enable",
        description: "Overrides Rx_only mode and forces transmission (requires local operator intervention).",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: None,
        execute: |_args, context, _| {
            if matches!(context.current_mode, Mode::RTxCMode) {
                //usrp.set_tx_enabled(True)
                //usrp.set_rx_enabled(False)
                //execute_spawn_process("sudo", &[""]); 
                println!("Enabling Tx ...");
                Ok(())
            } else {
                Err("The 'force_tx_enable' command is only available in Radio Transmission Control Mode.".into())
            }
        },
    });

    //Reset RF settings
    commands.insert("reset_rf_settings", Command {
        name: "reset_rf_settings",
        description: "Resets RF settings to default values.",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: None,
        execute: |_args, context, _| {
            if matches!(context.current_mode, Mode::RTxCMode) {
                //uhd_usrp_probe --reset
                //execute_spawn_process("sudo", &[""]); 
                println!("Reseting RF activity ...");
                Ok(())
            } else {
                Err("The 'reset_rf_settings' command is only available in Radio Transmission Control Mode.".into())
            }
        },
    });

    //Set the emission timer
    commands.insert("set_emcon_timer", Command {
        name: "set_emcon_timer",
        description: "Enables EMCON mode for a specified duration, after which emissions are automatically re-enabled.",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: Some(vec!["<time>        - Enter time in seconds"]),
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::RTxCMode) {
                if args.len() == 1 {
                    let time = &args[0];
                    //uhd_usrp_probe --tx_disable
                    //sleep 60
                    //uhd_usrp_probe --tx_enable
                    //execute_spawn_process("sudo", &[""]); 
                    println!("Srtting the emmision time to {} s", time);
                    Ok(()) 
                }else {
                    Err("The command is 'set_emcon_timer <time>'".into())
                }
            } else {
                Err("The 'set_emcon_timer' command is only available in Radio Transmission Control Mode.".into())
            }
        },
    });

    //Getting Emmission status
    commands.insert("get_emcon_status", Command {
        name: "get_emcon_status",
        description: "Returns the status of EMCON mode, including remaining time if a timer is set.",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: None,
        execute: |_args, context, _| {
            if matches!(context.current_mode, Mode::RTxCMode) {
                //uhd_usrp_probe
                //execute_spawn_process("sudo", &[""]); 
                println!("Locking RF activity ...");
                Ok(())
            } else {
                Err("The 'get_emcon_status' command is only available in Radio Transmission Control Mode.".into())
            }
        },
    });

    //Enable Rx Only
    commands.insert("enable_rx_only_override", Command {
        name: "enable_rx_only_override",
        description: "Allows remote control to disable Rx_only mode when necessary (future SEM improvement).",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: Some(vec!["<on|off>        - Mention the status on or off"]),
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::RTxCMode) {
                if args.len() == 1 && args[0] == "on" {
                    //uhd_usrp_probe --rx-only
                    //execute_spawn_process("sudo", &[""]); 
                    println!("Rx only mode enabled");
                    Ok(())
                } else if args.len() == 1 && args[0] == "off" {
                    //uhd_usrp_probe --tx-on
                    //execute_spawn_process("sudo", &[""]); 
                    println!("Rx only mode disabled");
                    Ok(()) 
                }else {
                    Err("The command is 'enable_rx_only_override [on|off]'".into())
                }
            } else {
                Err("The 'enable_rx_only_override' command is only available in Radio Transmission Control Mode.".into())
            }
        },
    });

    //Log RF activity
    commands.insert("log_rf_activity", Command {
        name: "log_rf_activity",
        description: "Retrieves a log of recent RF mode changes and power adjustments.",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: None,
        execute: |_args, context, _| {
            if matches!(context.current_mode, Mode::RTxCMode) {
                //uhd_usrp_probe --verbose
                //execute_spawn_process("sudo", &[""]); 
                println!("Locking RF activity ...");
                Ok(())
            } else {
                Err("The 'log_rf_activity' command is only available in Radio Transmission Control Mode.".into())
            }
        },
    });

    //--------------------------------------------------------------------------------------------------------------------------------
    //Information Distribution Mode Commands

    //Setting the PnF Box state
    commands.insert("set_mode", Command {
        name: "set_mode",
        description: "Configures the PnF Box to operate as a source, sink, or relay.",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: Some(vec!["<source/sink/relay>        - Mention the status"]),
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::InfoDistMode) {
                if args.len() == 1 && args[0] == "source" {
                    //execute_spawn_process("sudo", &[""]); 
                    println!("PnF Box is operating as a source");
                    Ok(())
                } else if args.len() == 1 && args[0] == "sink" {
                    //execute_spawn_process("sudo", &[""]); 
                    println!("PnF Box is operating as a sink");
                    Ok(()) 
                }
                 else if args.len() == 1 && args[0] == "relay" {
                    //Allow ip packet forwarding
                    //execute_spawn_process("sudo", &[""]); 
                    println!("PnF Box is operating as a relay");
                    Ok(()) 
                }else {
                    Err("The command is 'set_mode [source|sink|relay]'".into())
                }
            } else {
                Err("The 'set_mode' command is only available in Information Distribution Mode.".into())
            }
        },
    });

    //Enabling relay
    commands.insert("enable_relay", Command {
        name: "enable relay",
        description: "Activates the relay function, allowing the system to forward incoming data.",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: None,
        execute: |_args, context, _| {
            if matches!(context.current_mode, Mode::InfoDistMode) {
                //Allow ip packets
                //sudo nano /etc/sysctl.conf
                //net.ipv4.ip_forward=1
                //sudo sysctl -p
                //execute_spawn_process("sudo", &[""]); 
                println!("Enabling Relay...");
                Ok(())
            } else {
                Err("The 'enable_relay' command is only available in Information Distribution Mode.".into())
            }
        },
    });

    //Disabling relay
    commands.insert("disable_relay", Command {
        name: "disable relay",
        description: "Disables the relay function, preventing the system from forwarding data.",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: None,
        execute: |_args, context, _| {
            if matches!(context.current_mode, Mode::InfoDistMode) {
                //#net.ipv4.ip_forward=1 --> comment this and restart
                //sudo sysctl -p
                //execute_spawn_process("sudo", &[""]); 
                println!("Disabling Relay...");
                Ok(())
            } else {
                Err("The 'disable_relay' command is only available in Information Distribution Mode.".into())
            }
        },
    });

    //get the mode
    commands.insert("get_mode", Command {
        name: "get_mode",
        description: "Retrieves the current operating mode (source, sink, or relay).",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: None,
        execute: |_args, context, _| {
            if matches!(context.current_mode, Mode::InfoDistMode) {
                //execute_spawn_process("sudo", &[""]); 
                println!("Getting the current Mode...");
                Ok(())
            } else {
                Err("The 'get_mode' command is only available in Information Distribution Mode.".into())
            }
        },
    });

    //Get relay status
    commands.insert("get_relay_status", Command {
        name: "get_relay_status",
        description: "Checks whether the relay function is enabled or disabled.",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: None,
        execute: |_args, context, _| {
            if matches!(context.current_mode, Mode::InfoDistMode) {
                //sysctl net.ipv4.conf.all.forwarding
                //execute_spawn_process("sudo", &[""]); 
                println!("Getting Relay status...");
                Ok(())
            } else {
                Err("The 'get_relay_status' command is only available in Information Distribution Mode.".into())
            }
        },
    });

    //Log the relay activity
    commands.insert("log_relay_activity", Command {
        name: "log_relay_activity",
        description: "Fetches logs of recent relay operations for auditing and troubleshooting.",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: None,
        execute: |_args, context, _| {
            if matches!(context.current_mode, Mode::InfoDistMode) {
                //sudo dmesg | grep "FORWARD_LOG"
                //execute_spawn_process("sudo", &[""]); 
                println!("Logging the relay activity...");
                Ok(())
            } else {
                Err("The 'log_relay_activity' command is only available in Information Distribution Mode.".into())
            }
        },
    });

    //Set QOS priority
    commands.insert("set_qos_priority", Command {
        name: "set_qos_priority",
        description: "Defines Quality of Service (QoS) levels for data forwarding in relay mode.",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: Some(vec!["<level>        - Enter QOS priority level"]),
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::InfoDistMode) {
                if args.len() == 1 {
                    let level = &args[0];
                    //execute_spawn_process("sudo", &[""]); 
                    println!("QOS priority level is set to {}", level);
                    Ok(())
                }else {
                    Err("The command is 'set_qos_priority <level>'".into())
                }
            } else {
                Err("The 'set_qos_priority' command is only available in Information Distribution Mode.".into())
            }
        },
    });

    //Force relay mode activation
    commands.insert("manual_override_relay", Command {
        name: "manual_override_relay",
        description: "Forces relay mode activation or deactivation, overriding automatic system settings.",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: None,
        execute: |_args, context, _| {
            if matches!(context.current_mode, Mode::InfoDistMode) {
                //execute_spawn_process("sudo", &[""]); 
                println!("Manuaaly overriding the relay");
                Ok(())
            } else {
                Err("The 'manual_override_relay' command is only available in Information Distribution Mode.".into())
            }
        },
    });

    //Set relay timeout
    commands.insert("set_relay_timeout", Command {
        name: "set_relay_timeout",
        description: "Specifies a time limit for how long the relay function remains active before auto-disabling.",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: Some(vec!["<timel>        - Define time in seconds"]),
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::InfoDistMode) {
                if args.len() == 1 {
                    let time = &args[0];
                    //execute_spawn_process("sudo", &[""]); 
                    println!("Relay timeout is set to {}s", time);
                    Ok(())
                }else {
                    Err("The command is 'set_relay_timeout <time>'".into())
                }
            } else {
                Err("The 'set_relay_timeout' command is only available in Information Distribution Mode.".into())
            }
        },
    });

    //Get relay timeout
    commands.insert("get_relay_timeout", Command {
        name: "get_relay_timeout",
        description: "Retrieves the current relay timeout setting.",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: None,
        execute: |_args, context, _| {
            if matches!(context.current_mode, Mode::InfoDistMode) {
                //execute_spawn_process("sudo", &[""]); 
                println!("Getting relay timeout...");
                Ok(())
            } else {
                Err("The 'get_relay_timeout' command is only available in Information Distribution Mode.".into())
            }
        },
    });

    //Reset relay settingsn
    commands.insert("reset_relay_settings", Command {
        name: "reset_relay_settings",
        description: "Restores relay-related settings to default values.",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: None,
        execute: |_args, context, _| {
            if matches!(context.current_mode, Mode::InfoDistMode) {
                //execute_spawn_process("sudo", &[""]); 
                println!("Reset relay settings");
                Ok(())
            } else {
                Err("The 'reset_relay_settings' command is only available in Information Distribution Mode.".into())
            }
        },
    });

    //--------------------------------------------------------------------------------------------------------------------------------
    //System Monitoring Mode Commands

    //Giving full access to the remote user
    //Now the Local operator commands are blocked.
    commands.insert("remote_exclusive_access", Command {
        name: "remote_exclusive_access",
        description: "Allows the remote controller to take exclusive control of the PnF Box using the command",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: None,
        execute: |_args, context, _| {
            if matches!(context.current_mode, Mode::SysMonitorMode) {
                //execute_spawn_process("sudo", &[""]); 
                println!("Giving full access to the remote user");
                Ok(())
            } else {
                Err("The 'remote_exclusive_access' command is only available in System Monitoring Mode.".into())
            }
        },
    });

    //Blocking full access to the remote user
    commands.insert("release_remote_access", Command {
        name: "release_remote_access",
        description: "Restores local operator control.",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: None,
        execute: |_args, context, _| {
            if matches!(context.current_mode, Mode::SysMonitorMode) {
                //execute_spawn_process("sudo", &[""]); 
                println!("Restores local operator control.");
                Ok(())
            } else {
                Err("The 'release_remote_access' command is only available in System Monitoring Mode.".into())
            }
        },
    });

    //Giving details on remote access
    commands.insert("show_remote_access_status", Command {
        name: "show_remote_access_status",
        description: "Displays whether local or remote control is currently active.",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: None,
        execute: |_args, context, _| {
            if matches!(context.current_mode, Mode::SysMonitorMode) {
                //execute_spawn_process("sudo", &[""]); 
                println!("Giving remote access details");
                Ok(())
            } else {
                Err("The 'show_remote_access_status' command is only available in System Monitoring Mode.".into())
            }
        },
    });

    //Battleshort Mode Commands
    //Activate battleshort
    commands.insert("activate_battleshort", Command {
        name: "activate_battleshort",
        description: "Disables automatic decision-making, allowing the system to continue running until failure",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: None,
        execute: |_args, context, _| {
            if matches!(context.current_mode, Mode::SysMonitorMode) {
                //sudo systemctl stop watchdog
                //sudo systemctl disable watchdog
                //execute_spawn_process("sudo", &[""]); 
                println!("Battleshort mode is activated");
                Ok(())
            } else {
                Err("The 'activate_battleshort' command is only available in System Monitoring Mode.".into())
            }
        },
    });

    //Deactivate battleshort
    commands.insert("deactivate_battleshort", Command {
        name: "deactivate_battleshort",
        description: "Restores normal system protections and automated recovery mechanisms.",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: None,
        execute: |_args, context, _| {
            if matches!(context.current_mode, Mode::SysMonitorMode) {
                //sudo systemctl enable watchdog
                //sudo systemctl start watchdog
                //execute_spawn_process("sudo", &[""]); 
                println!("Battleshort mode is deactivated");
                Ok(())
            } else {
                Err("The 'deactivate_battleshort' command is only available in System Monitoring Mode.".into())
            }
        },
    });

    //Show battleshort status
    commands.insert("battleshort_status", Command {
        name: "battleshort_status",
        description: "Retrieves the current battleshort mode state.",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: None,
        execute: |_args, context, _| {
            if matches!(context.current_mode, Mode::SysMonitorMode) {
                //cat /proc/sys/kernel/watchdog --> 1-enabled, 0-disabled
                //execute_spawn_process("sudo", &[""]); 
                println!("Giving battleshort status");
                Ok(())
            } else {
                Err("The 'battleshort_status' command is only available in System Monitoring Mode.".into())
            }
        },
    });

    //set_syslog_server 
    commands.insert("set_syslog_server", Command {
        name: "set_syslog_server",
        description: "Configures the Syslog server address and port.",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: Some(vec!["<IP>        - Define the IP address",
        "<port_number>        - Define the port number"]),
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::SysMonitorMode) {
                if args.len() == 2 {
                    let ip_addr = &args[0];
                    let port_no = &args[1];
                    //sudo nano /etc/rsyslog.conf
                    // and then add --> *.* @@<syslog-server-ip>:<port>  # TCP (default port 514)
                    //sudo systemctl restart rsyslog
                    //execute_spawn_process("sudo", &[""]); 
                    println!("Set the syslog server to {} and {}", ip_addr, port_no);
                    Ok(())
                }else {
                    Err("The command is 'set_syslog_server <IP_address> <port_number>'".into())
                }
            } else {
                Err("The 'set_syslog_server' command is only available in System Monitoring Mode.".into())
            }
        },
    });

    //enable syslog 
    commands.insert("enable_syslog", Command {
        name: "enable_syslog",
        description: "Activates Syslog forwarding with the specified log level.",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: Some(vec!["<level>        - Define the log level",]),
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::SysMonitorMode) {
                if args.len() == 1 {
                    let level = &args[0];
                    //sudo systemctl enable rsyslog
                    //execute_spawn_process("sudo", &[""]); 
                    println!("Activates Syslog forwarding with {} log level.", level);
                    Ok(())
                }else {
                    Err("The command is 'enable_syslog <level>'".into())
                }
            } else {
                Err("The 'enable_syslog' command is only available in System Monitoring Mode.".into())
            }
        },
    });

    //disable syslog
    commands.insert("disable_syslog", Command {
        name: "disable_syslog",
        description: "Disables Syslog forwarding..",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: None,
        execute: |_args, context, _| {
            if matches!(context.current_mode, Mode::SysMonitorMode) {
                //sudo systemctl disable rsyslog
                //sudo systemctl stop rsyslog
                //execute_spawn_process("sudo", &[""]); 
                println!("Disables Syslog forwarding.");
                Ok(())
            } else {
                Err("The 'disable_syslog' command is only available in System Monitoring Mode.".into())
            }
        },
    });

    //testing syslog
    commands.insert("test_syslog", Command {
        name: "test_syslog",
        description: "Sends a test log entry to verify Syslog connectivity.",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: None,
        execute: |_args, context, _| {
            if matches!(context.current_mode, Mode::SysMonitorMode) {
                //logger -n <syslog-server-ip> -P <port> "Test log message from $(hostname)"
                //execute_spawn_process("sudo", &[""]); 
                println!("Testing syslog");
                Ok(())
            } else {
                Err("The 'test_syslog' command is only available in System Monitoring Mode.".into())
            }
        },
    });

    //show syslog status
    commands.insert("show_syslog_status", Command {
        name: "show_syslog_status",
        description: "Displays current Syslog configuration.",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: None,
        execute: |_args, context, _| {
            if matches!(context.current_mode, Mode::SysMonitorMode) {
                //sudo systemctl status rsyslog
                //execute_spawn_process("sudo", &[""]); 
                println!("Syslog status...");
                Ok(())
            } else {
                Err("The 'show_syslog_status' command is only available in System Monitoring Mode.".into())
            }
        },
    });

    //show last log entries
    commands.insert("show_log", Command {
        name: "show_log",
        description: "Retrieves the last n system log entries.",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: Some(vec!["<number>        - Define the number of log levels needed",]),
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::SysMonitorMode) {
                if args.len() == 1 {
                    let level = &args[0];
                    //journalctl --> and then log into a file
                    //execute_spawn_process("sudo", &[""]); 
                    println!("Showing the last {} logs.", level);
                    Ok(())
                }else {
                    Err("The command is 'show_log <number>'".into())
                }
            } else {
                Err("The 'show_log' command is only available in System Monitoring Mode.".into())
            }
        },
    });

    //set alert 
    commands.insert("set_alert", Command {
        name: "set_alert",
        description: "Defines a custom alert threshold.",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: Some(vec!["<param>        - Define the parameter",
        "<value>        - Set the value"]),
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::SysMonitorMode) {
                if args.len() == 2 {
                    let param = &args[0];
                    let value = &args[1];
                    //Set the dafult values first
                    //execute_spawn_process("sudo", &[""]); 
                    println!("Defines a custom alert threshold for {} with the value {}.", param, value);
                    Ok(())
                }else {
                    Err("The command is 'set_alert <param> <value>'".into())
                }
            } else {
                Err("The 'set_alert' command is only available in System Monitoring Mode.".into())
            }
        },
    });

    //get alerts
    commands.insert("get_alerts", Command {
        name: "get_alerts",
        description: "Lists active alert configurations.",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: None,
        execute: |_args, context, _| {
            if matches!(context.current_mode, Mode::SysMonitorMode) {
                //Get the current cpu value --> top -bn1 | grep "Cpu(s)" | awk '{print 100 - $8}' 
                //Get the current memory usage --> free | awk '/Mem:/ { printf("%.0f"), $3/$2 * 100.0 }'
                //Get the current disk usage --> df / | grep / | awk '{ print $5 }' | sed 's/%//g'
                //Get the current time drift --> chronyc tracking | grep "Last offset" | awk '{print $4}'
                //then compare the values and issue alerts
                //execute_spawn_process("sudo", &[""]); 
                println!("Lists active alert configurations.");
                Ok(())
            } else {
                Err("The 'get_alerts' command is only available in System Monitoring Mode.".into())
            }
        },
    });

    //Get system health
    commands.insert("snmpget", Command {
        name: "snmpget",
        description: "Fetches real-time system health status via SNMP.",
        suggestions: Some(vec!["sysHealth"]),
        suggestions1: Some(vec!["sysHealth"]),
        suggestions2: None,
        options: None,
        execute: |_args, context, _| {
            if matches!(context.current_mode, Mode::SysMonitorMode) {
                //snmpget -v2c -c public localhost SNMPv2-MIB::sysUpTime.0
                //snmpget -v2c -c public localhost UCD-SNMP-MIB::laLoad.1
                //snmpget -v2c -c public localhost UCD-SNMP-MIB::memTotalReal.0 UCD-SNMP-MIB::memAvailReal.0
                //snmpwalk -v2c -c public localhost HOST-RESOURCES-MIB::hrStorage
                //Get the outputs to one file and get the output
                //execute_spawn_process("sudo", &[""]); 
                println!("Getting snmp system health");
                Ok(())
            } else {
                Err("The 'snmpget sysHealth' command is only available in System Monitoring Mode.".into())
            }
        },
    });

    //Send SNMP traps
    commands.insert("snmptrap", Command {
        name: "snmptrap",
        description: "Manually triggers an SNMP trap.",
        suggestions: Some(vec!["send"]),
        suggestions1: Some(vec!["send"]),
        suggestions2: None,
        options: Some(vec!["<event>        - Define the event"]),
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::SysMonitorMode) {
                if args.len() == 2 && args[0] == "send" {
                    let event = &args[1];
                    //Manual trap --> snmptrap -v2c -c public 192.168.1.100 "" UCD-SNMP-MIB::ucdStart
                    //custom alert --> snmptrap -v2c -c public 192.168.1.100 "" .1.3.6.1.4.1.2021.51.101.1 s "High CPU Usage Detected!"
                    //execute_spawn_process("sudo", &[""]); 
                    println!("Manually triggers an SNMP trap for the event {}.", event);
                    Ok(())
                }else {
                    Err("The command is 'snmptrap send <event>'".into())
                }
            } else {
                Err("The 'snmptrap send' command is only available in System Monitoring Mode.".into())
            }
        },
    });

    //show_error_log
    commands.insert("show_error_log", Command {
        name: "show_error_log",
        description: "Retrieves the last critical error codes and warnings..",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: None,
        execute: |_args, context, _| {
            if matches!(context.current_mode, Mode::SysMonitorMode) {
                //journalctl -p 3 -n 20 --> p=3 errors, p=4 warnings
                //dmesg --level=err,warn | tail -20 --> kernal erros
                //snmpwalk -v2c -c public localhost .1.3.6.1.4.1.2021.2.1 --> snmp
                //grep -i "error\|fail\|critical" /var/log/syslog | tail -20 --> syslog
                //execute_spawn_process("sudo", &[""]); 
                println!("Retrieves the last critical error codes and warnings.");
                Ok(())
            } else {
                Err("The 'show_error_log' command is only available in System Monitoring Mode.".into())
            }
        },
    });

    //clear_ui_display
    commands.insert("clear_ui_display", Command {
        name: "clear_ui_display",
        description: "Clears error messages from the UI display.",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: None,
        execute: |_args, context, _| {
            if matches!(context.current_mode, Mode::SysMonitorMode) {
                //sudo systemctl disable apport.service
                //execute_spawn_process("sudo", &[""]); 
                println!("Clears error messages from the UI display");
                Ok(())
            } else {
                Err("The 'clear_ui_display' command is only available in System Monitoring Mode.".into())
            }
        },
    });

    //test_ui_alert
    commands.insert("test_ui_alert", Command {
        name: "test_ui_alert",
        description: "Sends a test alert to the UI MCU for verification.",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: None,
        execute: |_args, context, _| {
            if matches!(context.current_mode, Mode::SysMonitorMode) {
                //
                //execute_spawn_process("sudo", &[""]); 
                println!("Sends a test alert to the UI MCU for verification.");
                Ok(())
            } else {
                Err("The 'test_ui_alert' command is only available in System Monitoring Mode.".into())
            }
        },
    });

    //--------------------------------------------------------------------------------------------------------------------------------
    //High Availability Config Mode Commands

    //Set roles
    commands.insert("set_role", Command {
        name: "set_role",
        description: "Assigns a node as the active or standby system.",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: Some(vec!["<active|standby>        - Define the parameter"]),
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::HighAvaMode) {
                if args.len() == 1 && args[0] == "active" {
                    //sudo apt update && sudo apt install -y pacemaker pcs corosync
                    //sudo systemctl enable pcsd
                    //sudo systemctl start pcsd
                    //sudo pcs resource move <RESOURCE_NAME> <NODE_NAME>
                    //execute_spawn_process("sudo", &[""]); 
                    println!("Node set for active");
                    Ok(())
                } else if args.len() == 1 && args[0] == "standby" {
                    //sudo pcs resource move <RESOURCE_NAME> <NODE_NAME>
                    //execute_spawn_process("sudo", &[""]); 
                    println!("Node set for standby");
                    Ok(())
                }
                else {
                    Err("The command is 'set_role <active|standby>'".into())
                }
            } else {
                Err("The 'set_role' command is only available in Hight Availability Config Mode.".into())
            }
        },
    });

    //get role
    commands.insert("get_role", Command {
        name: "get_role",
        description: "Retrieves the current role of the node (active/standby).",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: None,
        execute: |_args, context, _| {
            if matches!(context.current_mode, Mode::HighAvaMode) {
                //sudo pcs status
                //execute_spawn_process("sudo", &[""]); 
                println!("Retrieves the current role of the node (active/standby).");
                Ok(())
            } else {
                Err("The 'get_role' command is only available in High Availability Config Mode.".into())
            }
        },
    });

    //force failover
    commands.insert("force_failover", Command {
        name: "force_failover",
        description: "Manually triggers failover to the standby node.",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: None,
        execute: |_args, context, _| {
            if matches!(context.current_mode, Mode::HighAvaMode) {
                //sudo pcs cluster standby <NODE_NAME>
                //execute_spawn_process("sudo", &[""]); 
                println!("Manually triggers failover to the standby node.");
                Ok(())
            } else {
                Err("The 'force_failover' command is only available in High Availability Config Mode.".into())
            }
        },
    });

    //enable auto failover
    commands.insert("enable_auto_failover", Command {
        name: "enable_auto_failover",
        description: "Activates automatic failover when failures are detected.",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: None,
        execute: |_args, context, _| {
            if matches!(context.current_mode, Mode::HighAvaMode) {
                //sudo pcs property set no-quorum-policy=ignore
                //execute_spawn_process("sudo", &[""]); 
                println!("Activates automatic failover when failures are detected.");
                Ok(())
            } else {
                Err("The 'enable_auto_failover' command is only available in High Availability Config Mode.".into())
            }
        },
    });

    //disable auto failover
    commands.insert("disable_auto_failover", Command {
        name: "disable_auto_failover",
        description: "Disables automatic failover, requiring manual intervention.",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: None,
        execute: |_args, context, _| {
            if matches!(context.current_mode, Mode::HighAvaMode) {
                //sudo pcs property set stonith-enabled=false
                //execute_spawn_process("sudo", &[""]); 
                println!("Disables automatic failover, requiring manual intervention.");
                Ok(())
            } else {
                Err("The 'disable_auto_failover' command is only available in High Availability Config Mode.".into())
            }
        },
    });

    //Set high priority value
    commands.insert("set_ha_priority", Command {
        name: "set_ha_priority",
        description: "Defines a priority level for failover (higher values = higher priority).",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: Some(vec!["<value>        - Define the priority value"]),
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::HighAvaMode) {
                if args.len() == 1  {
                    let value = &args[0];
                    //sudo pcs resource defaults migration-threshold=3
                    //execute_spawn_process("sudo", &[""]); 
                    println!("High priority value is set to {}", value);
                    Ok(())
                } 
                else {
                    Err("The command is 'set_ha_priority <value>'".into())
                }
            } else {
                Err("The 'set_ha_priority' command is only available in Hight Availability Config Mode.".into())
            }
        },
    });

    //get_ha_priority
    commands.insert("get_ha_priority", Command {
        name: "get_ha_priority",
        description: "Retrieves the currently configured failover priority level.",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: None,
        execute: |_args, context, _| {
            if matches!(context.current_mode, Mode::HighAvaMode) {
                //sudo pcs resource defaults | grep migration-threshold
                //execute_spawn_process("sudo", &[""]); 
                println!("Retrieves the currently configured failover priority level.");
                Ok(())
            } else {
                Err("The 'get_ha_priority' command is only available in High Availability Config Mode.".into())
            }
        },
    });

    //sync_stater
    commands.insert("sync_state", Command {
        name: "sync_state",
        description: "Forces synchronization between the active and standby nodes.",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: None,
        execute: |_args, context, _| {
            if matches!(context.current_mode, Mode::HighAvaMode) {
                //sudo drbdadm primary --force <RESOURCE_NAME>
                //execute_spawn_process("sudo", &[""]); 
                println!("Forces synchronization between the active and standby nodes.");
                Ok(())
            } else {
                Err("The 'sync_state' command is only available in High Availability Config Mode.".into())
            }
        },
    });

    //get_sync_status
    commands.insert("get_sync_status", Command {
        name: "get_sync_status",
        description: "Displays the status of the last synchronization event.",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: None,
        execute: |_args, context, _| {
            if matches!(context.current_mode, Mode::HighAvaMode) {
                //sudo drbdadm status
                //execute_spawn_process("sudo", &[""]); 
                println!("Displays the status of the last synchronization event.");
                Ok(())
            } else {
                Err("The 'get_sync_status' command is only available in High Availability Config Mode.".into())
            }
        },
    });

    //get_health_status
    commands.insert("get_health_status", Command {
        name: "get_health_status",
        description: "Retrieves system health metrics (CPU, memory, network, etc.).",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: None,
        execute: |_args, context, _| {
            if matches!(context.current_mode, Mode::HighAvaMode) {
                //top -bn1 | grep "Cpu(s)"
                //free -h
                //df -h
                //ip a
                //systemctl list-units --type=service --state=running
                //timedatectl
                //htop
                //execute_spawn_process("sudo", &[""]); 
                println!("Retrieves system health metrics (CPU, memory, network, etc.).");
                Ok(())
            } else {
                Err("The 'get_health_status' command is only available in High Availability Config Mode.".into())
            }
        },
    });

    //enable_snmp_notifications
    commands.insert("enable_snmp_notifications", Command {
        name: "enable_snmp_notifications",
        description: "Enables SNMP v3 alerts for high-availability events.",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: None,
        execute: |_args, context, _| {
            if matches!(context.current_mode, Mode::HighAvaMode) {
                //sudo nano /etc/snmp/snmpd.conf --> in this file edit
                //defaultMonitors yes
                //sudo systemctl restart snmpd  --> restart
                //execute_spawn_process("sudo", &[""]); 
                println!("Enables SNMP v3 alerts for high-availability events.");
                Ok(())
            } else {
                Err("The 'enable_snmp_notifications' command is only available in High Availability Config Mode.".into())
            }
        },
    });

    //disable_snmp_notifications
    commands.insert("disable_snmp_notifications", Command {
        name: "disable_snmp_notifications",
        description: "Disables SNMP alerts.",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: None,
        execute: |_args, context, _| {
            if matches!(context.current_mode, Mode::HighAvaMode) {
                //defaultMonitors no --> and then restart
                //execute_spawn_process("sudo", &[""]); 
                println!("Disables SNMP alerts.");
                Ok(())
            } else {
                Err("The 'disable_snmp_notifications' command is only available in High Availability Config Mode.".into())
            }
        },
    });

    //get_snmp_status
    commands.insert("get_snmp_status", Command {
        name: "get_snmp_status",
        description: "Checks whether SNMP alerts are enabled or disabled.",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: None,
        execute: |_args, context, _| {
            if matches!(context.current_mode, Mode::HighAvaMode) {
                //cat /etc/snmp/snmpd.conf | grep -E "trap|sink"
                //systemctl status snmpd
                //execute_spawn_process("sudo", &[""]); 
                println!("Checks whether SNMP alerts are enabled or disabled.");
                Ok(())
            } else {
                Err("The 'get_snmp_status' command is only available in High Availability Config Mode.".into())
            }
        },
    });

    //get_failover_logs
    commands.insert("get_failover_logs", Command {
        name: "get_failover_logs",
        description: "Fetches logs of recent failover events for auditing.",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: None,
        execute: |_args, context, _| {
            if matches!(context.current_mode, Mode::HighAvaMode) {
                //journalctl -u pacemaker
                //execute_spawn_process("sudo", &[""]); 
                println!("Fetches logs of recent failover events for auditing.");
                Ok(())
            } else {
                Err("The 'get_failover_logs' command is only available in High Availability Config Mode.".into())
            }
        },
    });

    //set_failover_timeout 
    commands.insert("set_failover_timeout", Command {
        name: "set_failover_timeout",
        description: "Defines the timeout before failover is triggered.",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: Some(vec!["<seconds>        - Define the time in seconds"]),
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::HighAvaMode) {
                if args.len() == 1  {
                    let value = &args[0];
                    //pcs resource update <resource_name> op monitor interval=30s timeout=60s
                    //execute_spawn_process("sudo", &[""]); 
                    println!("Timeout is defined for {}s", value);
                    Ok(())
                } 
                else {
                    Err("The command is 'set_failover_timeout <senonds>'".into())
                }
            } else {
                Err("The 'set_failover_timeout' command is only available in Hight Availability Config Mode.".into())
            }
        },
    });

    //test_failover
    commands.insert("test_failover", Command {
        name: "test_failover",
        description: "Simulates a failover event for validation purposes.",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: None,
        execute: |_args, context, _| {
            if matches!(context.current_mode, Mode::HighAvaMode) {
                //pcs resource move <resource_name> <other_node>  --> force a failover resource
                //execute_spawn_process("sudo", &[""]); 
                println!("Simulates a failover event for validation purposes.");
                Ok(())
            } else {
                Err("The 'test_failover' command is only available in High Availability Config Mode.".into())
            }
        },
    });

    //reset_ha_settings
    commands.insert("reset_ha_settings", Command {
        name: "reset_ha_settings",
        description: "Restores HA configurations to default values.",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: None,
        execute: |_args, context, _| {
            if matches!(context.current_mode, Mode::HighAvaMode) {
                //pcs cluster destroy
                //pcs cluster setup --name mycluster node1 node2
                //pcs cluster start --all
                //execute_spawn_process("sudo", &[""]); 
                println!("Restores HA configurations to default values.");
                Ok(())
            } else {
                Err("The 'reset_ha_settings' command is only available in High Availability Config Mode.".into())
            }
        },
    });


    commands
}


fn copy_run_config(running_config: &str, destination: &str, context: &mut CliContext) -> Result<(), String> {
    if destination == "startup-config" {
        save_running_to_startup(context);
        Ok(())
    } else {
        // Assume destination is a filename
        let file_path = Path::new(destination);
        
        match File::create(file_path) {
            Ok(mut file) => {
                if let Err(err) = file.write_all(running_config.as_bytes()) {
                    eprintln!("Error writing to the file: {}", err);
                    return Err(err.to_string());
                }
                println!("Running configuration copied to {}", destination);
                Ok(())
            }
            Err(err) => {
                eprintln!("Error creating the file: {}", err);
                Err(err.to_string())
            }
        }
    }
}