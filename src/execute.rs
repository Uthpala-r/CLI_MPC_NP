use std::collections::HashMap;
use crate::Clock;
use crate::CliContext;
use crate::commandcompleter::CommandCompleter;
use crate::run_config::help_command;

#[derive(Clone)]
pub struct Command {
    pub name: &'static str,
    pub description: &'static str,
    pub suggestions: Option<Vec<&'static str>>,
    pub arg_suggest: Option<Vec<&'static str>>,
    pub suggestions1: Option<Vec<&'static str>>,
    pub suggestions2: Option<Vec<&'static str>>,
    pub options: Option<Vec<&'static str>>,
    pub execute: fn(&[&str], &mut CliContext, &mut Option<Clock>) -> Result<(), String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Mode {
    UserMode,
    PrivilegedMode,
    ConfigMode,
    InterfaceMode,
    VlanMode,
    QosMode,
    DynamicRMode,
    PortSMode,
    MonitoringMode,
    AutoDMode,

}

pub fn execute_command(input: &str, commands: &HashMap<&str, Command>, context: &mut CliContext, clock: &mut Option<Clock>, _completer: &mut CommandCompleter) {
    let mut normalized_input = input.trim();
    let showing_suggestions = normalized_input.ends_with('?');
    
    if showing_suggestions {
        normalized_input = normalized_input.trim_end_matches('?');
    }
     
    let parts: Vec<&str> = normalized_input.split_whitespace().collect();
      
    let available_commands = get_mode_commands(commands, &context.current_mode);

    // Handle command execution (when no '?' is present)
    if !showing_suggestions {
        let cmd_key = parts[0];
        
        // Check if command exists in current mode
        let cmd_in_current_mode = find_unique_command(cmd_key, &available_commands);
        
        if let Some(matched_cmd) = cmd_in_current_mode {
            execute_matched_command(matched_cmd, &parts, commands, context, clock);
        }
        return;
    }

    // Handle suggestions '?' logic
    match parts.len() {
        0 => {
            // Handle single word with ? (e.g., "?")
            help_command(&context);
            
        },            
        1 => {
            let command_name = parts[0].trim();
            // Handle single word with ? (e.g., "configure ?")
            let available_commands = get_mode_commands(commands, &context.current_mode);
            if available_commands.contains(&command_name) {
                // If it's an exact command match, show its subcommands
                if let Some(cmd) = commands.get(command_name) {
                    if let Some(suggestions) = &cmd.suggestions1 {
                        println!("Possible completions:");
                        for suggestion in suggestions {
                            println!("  {}", suggestion);
                        }
                    } else if let Some(options) = &cmd.options {
                        // Fall back to options if no suggestions1 are available
                        println!("Possible completions:");
                        for option in options {
                            println!("  {}", option);
                        }
                    }else if command_name == "show" {
                        if matches!(context.current_mode, Mode::UserMode){
                            //println!("Possible Completions");
                            println!(r#"version
clock
uptime
controllers
history
sessions
arp"#);
                        } else {
                            //println!("Possible Completions");
                            println!(r#"running-config
startup-config
version
ntp
processes
clock
uptime
history
interfaces
ip
login
arp"#);
                        }
                    }  else if command_name == "config" {
                        if matches!(context.current_mode, Mode::PrivilegedMode){
                            //println!("Possible Completions");
                            println!("network_manager");
                        } else if matches!(context.current_mode, Mode::DynamicRMode){
                            //println!("Possible Completions");
                            println!(r#"ospf
rip
vlan
qosr
dynrouter
portsec
mon
autod"#);
                        } 
                        else if !matches!(context.current_mode, Mode::UserMode | Mode::PrivilegedMode){
                            //println!("Possible Completions");
                            println!(r#"vlan
qosr
dynrouter
portsec
mon
autod"#);
                        } 
                    } else if command_name == "enable" {
                        if matches!(context.current_mode, Mode::ConfigMode){
                            //println!("Possible Completions");
                            println!(r#"password
secret
network_manager"#);
                        } else if matches!(context.current_mode, Mode::VlanMode){
                            //println!("Possible Completions");
                            println!(r#"vlan_manager
bridge
router
protocol
id
vlan_tagging
vlan_routing"#);
                        }
                        else if matches!(context.current_mode, Mode::QosMode){
                            //println!("Possible Completions");
                            println!(r#"qos_manager"#);
                        }
                        else if matches!(context.current_mode, Mode::DynamicRMode){
                            //println!("Possible Completions");
                            println!(r#"dynamic_router_manager
ospf
rip
ospf_controller
rip_controller"#);
                        }
                        else if matches!(context.current_mode, Mode::PortSMode){
                            //println!("Possible Completions");
                            println!(r#"port_security_manager"#);
                        }
                        else if matches!(context.current_mode, Mode::MonitoringMode){
                            //println!("Possible Completions");
                            println!(r#"monitoring_manager
coredump_login"#);
                        }
                        else if matches!(context.current_mode, Mode::AutoDMode){
                            //println!("Possible Completions");
                            println!(r#"auto_discovery_manager"#);
                        }
                    } else if command_name == "disable" {
                        if matches!(context.current_mode, Mode::ConfigMode){
                            //println!("Possible Completions");
                            println!(r#"network_manager"#);
                        } else if matches!(context.current_mode, Mode::VlanMode){
                            //println!("Possible Completions");
                            println!(r#"vlan_manager"#);
                        }
                        else if matches!(context.current_mode, Mode::QosMode){
                            //println!("Possible Completions");
                            println!(r#"qos_manager"#);
                        }
                        else if matches!(context.current_mode, Mode::DynamicRMode){
                            //println!("Possible Completions");
                            println!(r#"dynamic_router_manager"#);
                        }
                        else if matches!(context.current_mode, Mode::PortSMode){
                            //println!("Possible Completions");
                            println!(r#"port_security_manager"#);
                        }
                        else if matches!(context.current_mode, Mode::MonitoringMode){
                            //println!("Possible Completions");
                            println!(r#"monitoring_manager"#);
                        }
                        else if matches!(context.current_mode, Mode::AutoDMode){
                            //println!("Possible Completions");
                            println!(r#"auto_discovery_manager"#);
                        }
                    }
                    else {
                        println!("No subcommands or more options available");
                    }
                }
            } else {
                // If it's a partial command, show matching commands
                let suggestions: Vec<&str> = available_commands
                    .into_iter()
                    .filter(|cmd| cmd.starts_with(command_name))
                    .collect();

                if !suggestions.is_empty() {
                    println!("Possible completions for '{}?':", command_name);
                    for suggestion in suggestions {
                        println!("  {}", suggestion);
                    }
                } 
                else {
                    if let Some(cmd) = commands.get(parts[0]) {
                        if let Some(options) = &cmd.options {
                            println!("Possible completions:");
                            for option in options {
                                println!("  {}", option);
                            }
                        } else {
                            println!("No more options available");
                        }
                    }
                }
            }
        },
        2 => {
            // Command with partial subcommand (e.g., "configure t?", "configure term?")
            let available_commands = get_mode_commands(commands, &context.current_mode);
            // Handle subcommand suggestions
            let command_name = parts[0];
            
            if available_commands.contains(&command_name) {
                if let Some(cmd) = commands.get(command_name) {
                    if !normalized_input.ends_with(' ') {
                        // Handle partial subcommand (e.g., "show i?")
                        if let Some(suggestions) = &cmd.suggestions1 {
                            let partial = parts[1];
                            let matching: Vec<&str> = suggestions
                                .iter()
                                .filter(|&&s| s.starts_with(partial))
                                .map(|&s| s)
                                .collect();
        
                            if !matching.is_empty() {
                                println!("Possible completions:");
                                for suggestion in matching {
                                    println!("  {}", suggestion);
                                }
                            } else {
                                println!("No matching commands found");
                            }
                        } else {
                            println!("No subcommands available");
                        }
                    } else {
                        // Handle full subcommand with question mark (e.g., "show ip ?")
                        let subcommand = *parts.get(1).unwrap_or(&"");
                        
                        // Special case handling for specific command-subcommand combinations
                        match command_name {
                            "do" => match subcommand {
                                "clock" => println!("set"),
                                "clear" => println!("ntp"),
                                "debug" | "undebug" => println!("all"),
                                _ => if let Some(suggestions) = &cmd.suggestions2 {
                                    println!("Possible completions:");
                                    for suggestion in suggestions {
                                        println!("  {}", suggestion);
                                    }
                                }
                            },
                            "show" => match subcommand {
                                "ip" => println!("interface     route"),
                                _ => if let Some(suggestions) = &cmd.suggestions2 {
                                    println!("Possible completions:");
                                    for suggestion in suggestions {
                                        println!("  {}", suggestion);
                                    }
                                }
                            },
                            "enable" => match subcommand {
                                "bridge" | "router" => println!("<name>         - Define the specified name"),
                                "protocol" => println!("<protocol>         - Define the protocol name"),
                                "id" => println!("<Id>         - Define the ID"),
                                "password" | "secret" => println!("<password|secret>         - Define the password or secret"),
                                "vlan_routing" => println!("id"),
                                "qos_manager" | "dynamic_routing_manager" => println!("id"),
                                _ => if let Some(suggestions) = &cmd.suggestions2 {
                                    println!("Possible completions:");
                                    for suggestion in suggestions {
                                        println!("  {}", suggestion);
                                    }
                                }
                            },
                            "clock" => match subcommand {
                                "set" => {
                                    println!("Possible completions:");
                                    println!("<hh:mm:ss>      - Enter the time in this specified format");
                                },
                                _ => if let Some(suggestions) = &cmd.suggestions2 {
                                    println!("Possible completions:");
                                    for suggestion in suggestions {
                                        println!("  {}", suggestion);
                                    }
                                }
                            },
                            "interface" => {
                                match context.current_mode {
                                    Mode::QosMode => {
                                        println!("Possible completions:");
                                        println!("<cpq|beq>");
                                    },
                                    Mode::AutoDMode => {
                                        println!("Possible completions:");
                                        println!("<enable|disable>   - Specify the condition");
                                        println!("mode");
                                    },
                                    _ => {
                                        if let Some(suggestions) = &cmd.suggestions2 {
                                            println!("Possible completions:");
                                            for suggestion in suggestions {
                                                println!("  {}", suggestion);
                                            }
                                        }
                                    }
                                }
                            },
                            "ssh" => match subcommand {
                                "-l" => {
                                    println!("Possible completions:");
                                    println!(r#"<user_name>       - Enter the user name"
        <IP-address>        - Enter the IP address"#);
                                },
                                "-v" => {
                                    println!("Possible completions:");
                                    println!("<version>        - Enter the version you need to change");
                                },
                                _ => if let Some(suggestions) = &cmd.suggestions2 {
                                    println!("Possible completions:");
                                    for suggestion in suggestions {
                                        println!("  {}", suggestion);
                                    }
                                }
                            },
                            
                            _ => if let Some(suggestions) = &cmd.suggestions2 {
                                println!("Possible completions:");
                                for suggestion in suggestions {
                                    println!("  {}", suggestion);
                                }
                            } else {
                                if let Some(cmd) = commands.get(parts[0]) {
                                    if let Some(options) = &cmd.options {
                                        println!("Possible completions:");
                                        for option in options {
                                            println!("  {}", option);
                                        }
                                    } else {
                                        println!("No more options available");
                                    }
                                }
                            }
                        }
                    }
                }
            } else {
                if let Some(cmd) = commands.get(parts[0]) {
                    if let Some(options) = &cmd.options {
                        println!("Possible completions:");
                        for option in options {
                            println!("  {}", option);
                        }
                    } else {
                        println!("No more options available");
                    }
                }
            }
        },
        3 => {
            // Handle third-level suggestions (e.g., after "ntp server" or "ntp source")
            let command_name = parts[0];
            let subcommand = parts[1];
            let param1 = parts[2];

            if command_name == "show" {
                if subcommand == "ip" {    
                    match param1 {
                        "interface" => {
                            println!(r#"brief
<interface>        - Enter a valid interface name"#);
                        },
                        _ => println!("No additional parameters available")
                    }
                }
            }
            else if command_name == "clock"{
                if subcommand == "set" {    
                    println!("Possible completions:");
                    println!("<day>      - Enter the day '1-31'");
                }
            }
            else if command_name == "interface"{
                if param1 == "mode" {    
                    println!("Possible completions:");
                    println!("<mode>      - Specify the mode");
                } else if param1 == "cpq" || param1 == "beq" {    
                    println!("Possible completions:");
                    println!("<true|false>      - Specify the condition");
                }
            }
            else if command_name == "priority"{
                if subcommand == "level" {    
                    println!("interface");
                }
            }
            else if command_name == "enable"{
                if param1 == "id" {    
                    println!("<ID>          - Define the ID");
                } else if subcommand == "router" {    
                    println!("id");
                } else if subcommand == "protocol" {    
                    println!("router");
                }
            }
            else if command_name == "add"{
                if subcommand == "bridge" {    
                    println!("interface");
                } else if subcommand == "interface" {    
                    println!("protocol");
                }
            }
            else if command_name == "ip"{
                if subcommand == "address" {    
                    println!("Possible completions:");
                    println!("<subnetmask>   - Enter the subnet mask");
                }
            } else if command_name == "network" {
                match param1{
                    "ip" => {
                        println!("Possible completions:");
                        println!("<ip_address>              - Enter the ip address");
                    },
                    "netmask" => {
                        println!("Possible completions:");
                        println!("<netmask>                 - Enter the netmask");
                    },
                    "area" => {
                        println!("Possible completions:");
                        println!("<area>                    - Enter the area");
                    },
                    _ => println!("No additional parameters available")
                }
            } 
            else if command_name == "do" {
                if subcommand == "show" {    
                    match param1 {
                        "ip" => {
                            println!("interface     route");
                        },
                        "ntp" => {
                            println!("associations");
                        },
                        _ => println!("No additional parameters available")
                    }
                }else if subcommand == "clear" {    
                    match param1 {
                        "ntp" => {
                            println!("associations");
                        },
                        _ => println!("No additional parameters available")
                    }
                } 
                else if subcommand == "copy" {    
                    match param1 {
                        "running-config" => {
                            println!("startup-config/<file-name>");
                        },
                        _ => println!("No additional parameters available")
                    }
                } else if subcommand == "clock" {    
                    match param1 {
                        "set" => {
                            println!(r#"<hh:mm:ss>   - Enter the time in this specified format"
"<day>      - Enter the day '1-31'"
"<month>    - Enter a valid month"
"<year>     - Enter the year"#);
                        },
                        _ => println!("No additional parameters available")
                    }
                }
            } 

            else {
                println!("No additional parameters available");
            }
        },
        4 => {
            // Special case for "do show ip something ?" command
            if parts[0] == "do" && parts[1] == "show" && parts[2] == "ip" {
                let param = parts[3];
                if param == "interface" {
                    println!("brief");
                    return;
                } else if param == "route" {
                    println!("No additional parameters available");
                    return;
                }
            }

            // Handle third-level suggestions (e.g., after "ntp server" or "ntp source")
            let command_name = parts[0];
            let subcommand = parts[1];

            if command_name == "clock"{
                match subcommand  {  
                    "set" => {  
                        println!("Possible completions:");
                        println!("<month>    - Enter a valid month");
                    },
                    _ => println!("No additional parameters available")
                }
            } 
            else if command_name == "priority"{
                match subcommand  {  
                    "level" => {  
                        println!("Possible completions:");
                        println!("<interface>    - Enter the interface name");
                    },
                    _ => println!("No additional parameters available")
                }
            } 
            else if command_name == "enable"{
                match subcommand  {  
                    "router" => {  
                        println!("Possible completions:");
                        println!("<ID>    - Enter the ID");
                    },
                    "protocol" => {  
                        println!("Possible completions:");
                        println!("<name>    - Define the router name");
                    },
                    _ => println!("No additional parameters available")
                }
            } 
            else if command_name == "add"{
                match subcommand  {  
                    "bridge" => {  
                        println!("Possible completions:");
                        println!("<interface_name>    - Define the interface name");
                    },
                    "interface" => {  
                        println!("Possible completions:");
                        println!("<protocol>    - Define the protocol");
                    },
                    _ => println!("No additional parameters available")
                }
            }
            else {
                println!("No additional parameters available");
            }
        },
        5 => {
            let command_name = parts[0];
            let subcommand = parts[1];

            if command_name == "add"{
                match subcommand  {  
                    "interface" => {  
                        println!("router");
                    },
                    _ => println!("No additional parameters available")
                }
            } 
        },
        6 => {
            let command_name = parts[0];
            let subcommand = parts[1];

            if command_name == "add"{
                match subcommand  {  
                    "interface" => {  
                        println!("Possible completions:");
                        println!("<router_name>    - Define the router name");
                    },
                    _ => println!("No additional parameters available")
                }
            } 
        },
        _ => {
            // Full command with ? (e.g., "configure terminal ?")
            println!("No additional parameters available");
        }
    }
    return;
}


fn execute_matched_command(matched_cmd: &str, parts: &[&str], commands: &HashMap<&str, Command>, context: &mut CliContext, clock: &mut Option<Clock>) {
    if let Some(cmd) = commands.get(matched_cmd) {
        execute_command_with_args(cmd, parts, context, clock);
    }
}

fn execute_command_with_args(cmd: &Command, parts: &[&str], context: &mut CliContext, clock: &mut Option<Clock>) {
    let result = if let Some(suggestions) = &cmd.arg_suggest {
        match parts.len() {
            1 => {
                // If it's an abbreviated command like "en" for "enable"
                if parts[0].starts_with("en") || parts[0].starts_with("int") || parts[0].starts_with("di"){
                    // Directly execute the command with no args
                    (cmd.execute)(&[], context, clock)
                } else {
                    println!("Incomplete command. Subcommand required.");
                    Ok(())
                }
            }
            2 => {
                if suggestions.is_empty() {
                    (cmd.execute)(&parts[1..], context, clock)
                } else {
                    if let Some(matched_subcommand) = find_unique_subcommand(parts[1], suggestions) {
                        (cmd.execute)(&[matched_subcommand], context, clock)
                    } else {
                        println!("Ambiguous or invalid subcommand: {}", parts[1]);
                        Ok(())
                    }
                }
            }
            _ => {
                (cmd.execute)(&parts[1..], context, clock)
            }
        }
    } else {
        (cmd.execute)(&parts[1..], context, clock)
    };

    // Handle errors from any of the command executions
    if let Err(err) = result {
        println!("Error: {}", err);
    }
}


// Get available commands for current mode
pub fn get_mode_commands<'a>(commands: &'a HashMap<&str, Command>, mode: &Mode) -> Vec<&'a str> {
    match mode {
        Mode::UserMode => {
            commands.keys()
                .filter(|&&cmd| {
                    cmd == "enable" ||
                    cmd == "ping" ||
                    cmd == "help" ||
                    cmd == "show" ||
                    cmd == "clear" ||
                    cmd == "reload" ||
                    cmd == "poweroff" ||
                    cmd == "connect" ||
                    cmd == "disable" ||
                    cmd == "ifconfig" ||
                    cmd == "traceroute" ||
                    cmd == "do" ||
                    cmd == "ip" ||
                    cmd == "write" ||
                    cmd == "dhcp_enable" ||
                    cmd == "exit"
                })
                .copied()
                .collect()
        },
        Mode::PrivilegedMode => {
            commands.keys()
                .filter(|&&cmd| {
                    cmd == "config" ||
                    cmd == "ping" || 
                    cmd == "exit" || 
                    cmd == "write" ||
                    cmd == "help" ||
                    cmd == "show" ||
                    cmd == "copy" ||
                    cmd == "clock" ||
                    cmd == "clear" ||
                    cmd == "reload" ||
                    cmd == "poweroff" ||
                    cmd == "debug" ||
                    cmd == "undebug" ||
                    cmd == "connect" ||
                    cmd == "disable" ||
                    cmd == "traceroute" ||
                    cmd == "ssh" ||
                    cmd == "do" ||
                    cmd == "ip" ||
                    cmd == "dhcp_enable" ||
                    cmd == "ifconfig"
                })
                .copied()
                .collect()
        },
        Mode::ConfigMode => {
            commands.keys()
                .filter(|&&cmd| {
                    cmd == "config" ||
                    cmd == "enable" ||
                    cmd == "hostname" || 
                    cmd == "ping" ||
                    cmd == "exit" ||
                    cmd == "clear" ||
                    cmd == "help" ||
                    cmd == "write" ||
                    cmd == "service" ||
                    cmd == "ifconfig" ||  
                    cmd == "no" || 
                    cmd == "reload" ||
                    cmd == "poweroff" ||
                    cmd == "connect" ||
                    cmd == "disable" ||
                    cmd == "traceroute" ||
                    cmd == "interface" ||
                    cmd == "ip" ||
                    cmd == "dhcp_enable" ||
                    cmd == "do"
                })
                .copied()
                .collect()
        },
        Mode::InterfaceMode => {
            commands.keys()
                .filter(|&&cmd| {
                    cmd == "shutdown" ||
                    cmd == "disable" ||
                    cmd == "no" ||
                    cmd == "exit" ||
                    cmd == "clear" ||
                    cmd == "help" ||
                    cmd == "write" ||
                    cmd == "reload" ||
                    cmd == "poweroff" ||
                    cmd == "ip" ||
                    cmd == "interface" ||
                    cmd == "do" 
                })
                .copied()
                .collect()
        }
        Mode::VlanMode => {
            commands.keys()
                .filter(|&&cmd| {
                    cmd == "config" ||
                    cmd == "enable" ||
                    cmd == "disable" ||
                    cmd == "exit" ||
                    cmd == "clear" ||
                    cmd == "help" ||
                    cmd == "reload" ||
                    cmd == "poweroff" ||
                    cmd == "do" ||
                    cmd == "bridge_name" ||
                    cmd == "vlan" ||
                    cmd == "segment" ||
                    cmd == "add" ||
                    cmd == "router" 
                })
                .copied()
                .collect()
        }
        Mode::QosMode => {
            commands.keys()
                .filter(|&&cmd| {
                    cmd == "config" ||
                    cmd == "enable" ||
                    cmd == "disable" ||
                    cmd == "exit" ||
                    cmd == "clear" ||
                    cmd == "help" ||
                    cmd == "reload" ||
                    cmd == "poweroff" ||
                    cmd == "do" ||
                    cmd == "policy" ||
                    cmd == "interface" ||
                    cmd == "priority" 
                })
                .copied()
                .collect()
        }
        Mode::DynamicRMode => {
            commands.keys()
                .filter(|&&cmd| {
                    cmd == "config" ||
                    cmd == "enable" ||
                    cmd == "network" ||
                    cmd == "redistribute" ||
                    cmd == "valid" ||
                    cmd == "controller" ||
                    cmd == "disable" ||
                    cmd == "exit" ||
                    cmd == "clear" ||
                    cmd == "help" ||
                    cmd == "reload" ||
                    cmd == "poweroff" ||
                    cmd == "do" 
                })
                .copied()
                .collect()
        }
        Mode::PortSMode => {
            commands.keys()
                .filter(|&&cmd| {
                    cmd == "config" ||
                    cmd == "enable" ||
                    cmd == "disable" ||
                    cmd == "exit" ||
                    cmd == "clear" ||
                    cmd == "help" ||
                    cmd == "reload" ||
                    cmd == "poweroff" ||
                    cmd == "do" ||
                    cmd == "mode" ||
                    cmd == "max_devices" ||
                    cmd == "violation_status" 
                })
                .copied()
                .collect()
        }
        Mode::MonitoringMode => {
            commands.keys()
                .filter(|&&cmd| {
                    cmd == "config" ||
                    cmd == "enable" ||
                    cmd == "disable" ||
                    cmd == "exit" ||
                    cmd == "clear" ||
                    cmd == "help" ||
                    cmd == "reload" ||
                    cmd == "poweroff" ||
                    cmd == "do" ||
                    cmd == "logging_level" 
                })
                .copied()
                .collect()
        }
        Mode::AutoDMode => {
            commands.keys()
                .filter(|&&cmd| {
                    cmd == "config" ||
                    cmd == "enable" ||
                    cmd == "disable" ||
                    cmd == "exit" ||
                    cmd == "clear" ||
                    cmd == "help" ||
                    cmd == "reload" ||
                    cmd == "poweroff" ||
                    cmd == "do" ||
                    cmd == "holdtime" ||
                    cmd == "interface" ||
                    cmd == "reinit" 
                })
                .copied()
                .collect()
        }
        
    }
}

pub fn find_unique_command<'a>(partial: &str, available_commands: &[&'a str]) -> Option<&'a str> {
    let matches: Vec<&str> = available_commands
        .iter()
        .filter(|&&cmd| cmd.starts_with(partial))
        .copied()
        .collect();

    if matches.len() == 1 {
        Some(matches[0])
    } else {
        None
    }
}

pub fn find_unique_subcommand<'a>(partial: &str, suggestions: &'a [&str]) -> Option<&'a str> {
    let matches: Vec<&str> = suggestions
        .iter()
        .filter(|&&s| s.starts_with(partial))
        .copied()
        .collect();

    if matches.len() == 1 {
        Some(matches[0])
    } else {
        None
    }
}

