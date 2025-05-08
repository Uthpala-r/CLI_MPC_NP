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
use crate::network_config::{terminate_ssh_session, get_available_int, ip_with_cidr, get_system_interfaces, connect_via_ssh, execute_spawn_process, IP_ADDRESS_STATE,  SELECTED_INTERFACE, ROUTE_TABLE};
use crate::passwd::{PASSWORD_STORAGE, set_enable_password, set_enable_secret, get_enable_password, get_enable_secret, encrypt_password};
use crate::show_c::{show_clock, show_uptime, show_version, show_sessions, show_controllers, show_history, show_run_conf, show_start_conf, show_interfaces, show_ip_int_br, show_ip_int_sp, show_ip_route, show_login, show_proc, show_arp};

/// Builds and returns a `HashMap` of available commands, each represented by a `Command` structure.

pub fn build_command_registry() -> HashMap<&'static str, Command> {
    let mut commands = HashMap::new();

    //Enter the Priviledged Exec Mode (Enable password and secret in Global Configuration mode)
    commands.insert("enable", Command {
        name: "enable",
        description: "Enter privileged EXEC mode",
        suggestions: Some(vec!["password", "secret", 
        "network_manager", "vlan_manager", "qos_manager", "dynamic_routing_manager", "port_security_manager", "monitoring_manager", "auto_discovery_manager", 
        "ospf", "ospf_controller", "rip", "rip_controller", 
        "coredump_login",
        "bridge", "router", "protocol", "id", "vlan_tagging", "vlan_routing",
        "qos_config"]),
        arg_suggest: Some(vec!["password", "secret", 
        "network_manager", "vlan_manager", "qos_manager", "dynamic_routing_manager", "port_security_manager", "monitoring_manager", "auto_discovery_manager", 
        "ospf", "ospf_controller", "rip", "rip_controller", 
        "coredump_login",
        "bridge", "router", "protocol", "id", "vlan_tagging", "vlan_routing",
        "qos_config"]),
        suggestions1: None,
        suggestions2: None,
        options: None,
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
                    "network_manager" => {
                        if matches!(context.current_mode, Mode::ConfigMode) {
                            println!("Network Manager is enabled.");
                            //Back-end implementation
                            //NetworkingManager.enabled=true 
                            Ok(())
                        } else {
                            Err("The 'enable network_manager' command is only available in Config mode.".into())
                        }
                    },
                    "vlan_manager" => {
                        if matches!(context.current_mode, Mode::VlanMode) {
                            println!("Vlan Manager is enabled.");
                            //Back-end implementation
                            //NetworkingManager.VlanManager.enabled=true
                            Ok(())
                        } else {
                            Err("The 'enable vlan_manager' command is only available in Vlan Manager mode.".into())
                        }
                    },
                    "qos_manager" => {
                        if matches!(context.current_mode, Mode::QosMode) {
                            if args.len() == 2 {  
                                let id = args[2];     
                                println!("QOS Manager for the id {} is enabled.", id);
                                //Back-end implementation
                                //NetworkingManager.QosManager.enabled=true 
                                Ok(())
                            } else{
                                Err("Correct usage: 'enable qos_manager id <ID>'".into())
                            }
                        } else {
                            Err("The 'enable qos_manager' command is only available in QOS Manager mode.".into())
                        }
                    },
                    "dynamic_routing_manager" => {
                        if matches!(context.current_mode, Mode::DynamicRMode) {
                            if args.len() == 3 {  
                                let id = args[2];  
                                println!("Dynamic Routing Manager for the id {} is enabled.", id);
                                //Back-end implementation
                                //NetworkingManager.DynamicRoutingManager[id=2].enabled=true 
                                Ok(())
                            } else{
                                Err("Correct usage: 'enable dynamic_routing_manager id <ID>'".into())
                            }
                        } else {
                            Err("The 'enable dynamic_routing_manager <ID>' command is only available in Dynamic Routing Manager mode.".into())
                        }
                    },
                    "port_security_manager" => {
                        if matches!(context.current_mode, Mode::PortSMode) {
                            println!("Port Security Manager is enabled.");
                            //Back-end implementation
                            //NetworkingManager.PortSecurityManager.enabled=true 
                            Ok(())
                        } else {
                            Err("The 'enable port_security_manager' command is only available in Port Security Manager mode.".into())
                        }
                    },
                    "monitoring_manager" => {
                        if matches!(context.current_mode, Mode::MonitoringMode) {
                            println!("Monitoring Manager is enabled.");
                            //Back-end implementation
                            //NetworkingManager.MonitoringManager.enabled=true 
                            Ok(())
                        } else {
                            Err("The 'enable monitoring_manager' command is only available in Monitoring Manager mode.".into())
                        }
                    },
                    "auto_discovery_manager" => {
                        if matches!(context.current_mode, Mode::AutoDMode) {
                            println!("Auto Discovery Manager is enabled.");
                            //Back-end implementation
                            //NetworkingManager.AutoDiscoveryManager.enabled=true
                            Ok(())
                        } else {
                            Err("The 'enable auto_discovery_manager' command is only available in Auto Discovery Manager mode.".into())
                        }
                    },
                    "ospf" => {
                        if matches!(context.current_mode, Mode::DynamicRMode) {
                            println!("OSPF routing is enabled.");
                            //Back-end implementation
                            //NetworkingManager.DynamicRoutingManager.OspfConfiguration.enabled=true 
                            Ok(())
                        } else {
                            Err("The 'enable ospf' command is only available in Dynamic Routing Manager mode.".into())
                        }
                    },
                    "ospf_controller" => {
                        if matches!(context.current_mode, Mode::DynamicRMode) {
                            println!("OSPF controller is enabled.");
                            //Back-end implementation
                            //NetworkingManager.DynamicRoutingManager.OspfController.enabled=true 
                            Ok(())
                        } else {
                            Err("The 'enable ospf_controller' command is only available in Dynamic Routing Manager mode.".into())
                        }
                    },
                    "rip" => {
                        if matches!(context.current_mode, Mode::DynamicRMode) {
                            println!("RIP routing is enabled.");
                            //Back-end implementation
                            //NetworkingManager.DynamicRoutingManager.RipConfiguration.enabled=true
                            Ok(())
                        } else {
                            Err("The 'enable rip' command is only available in Dynamic Routing Manager mode.".into())
                        }
                    },
                    "rip_controller" => {
                        if matches!(context.current_mode, Mode::DynamicRMode) {
                            println!("RIP controller is enabled.");
                            //Back-end implementation
                            //NetworkingManager.DynamicRoutingManager.RipController.enabled=true 
                            Ok(())
                        } else {
                            Err("The 'enable ospf_controller' command is only available in Dynamic Routing Manager mode.".into())
                        }
                    },
                    "coredump_login" => {
                        if matches!(context.current_mode, Mode::MonitoringMode) {
                            println!("Coredump login enabled");
                            //Back-end implementation
                            //NetworkingManager.MonitoringManager.logging.coredump.enabled=true 
                            Ok(())
                        } else {
                            Err("The 'enable coredump_login' command is only available in Monitoring Manager mode.".into())
                        }
                    },
                    "bridge" => {
                        if matches!(context.current_mode, Mode::VlanMode) {
                            if args.len() == 2 {
                                let name = args[1];
                                println!("Enables the bridge {}", name);
                                //Back-end implementation
                                //NetworkingManager.VlanManager.bridge[bridge1].enabled= true 
                                Ok(())
                            }
                            else {
                                Err("The correct usage : 'enable bridge <bridge_name>'".into())
                            }                            
                        } else {
                            Err("The 'enable bridge <bridge_name>' command is only available in VLAN Manager mode.".into())
                        }
                    },
                    "router" => {
                        if matches!(context.current_mode, Mode::VlanMode) {
                            if args.len() == 2 {
                                let name = args[1];
                                println!("Enables the router {}", name);
                                //Back-end implementation
                                //NetworkingManager.VlanManager.router[router1].enabled= true 
                                Ok(())
                            } else if args.len() == 4 && args[2] == "id" {
                                let name = args[1];
                                let id = args[3];
                                println!("Enables the router {} for the id {}", name, id);
                                //Back-end implementation
                                //NetworkingManager.VlanManager.router[router1].id= 2 
                                Ok(())
                            }
                            else {
                                Err("The correct usage : 'enable router <router_name>' or 'enable router <router_name> id <ID>'".into())
                            }
                        } else {
                            Err("The 'enable router <router_name>' command is only available in VLAN Manager mode.".into())
                        }
                    },
                    "protocol" => {
                        if matches!(context.current_mode, Mode::VlanMode) {
                            if args.len() == 4 && args[2] == "router" {
                                let protocol = args[1];
                                let name = args[3];
                                println!("Enables the router {} for the protocol {}", name, protocol);
                                //Back-end implementation
                                //NetworkingManager.VlanManager.router[router1].protocol[‘ospf].enabled = true
                                Ok(())
                            }
                            else {
                                Err("The correct usage : 'enable protocol <protocol> router <router_name>'".into())
                            } 
                        } else {
                            Err("The 'enable protocol <protocol> router <router_name>' command is only available in VLAN Manager mode.".into())
                        }
                    },
                    "id" => {
                        if matches!(context.current_mode, Mode::VlanMode) {
                            if args.len() == 2 {
                                let id = args[1];
                                println!("Enables the ID {}", id);
                                //Back-end implementation
                                //NetworkingManager.VlanManager.vlan[1].enabled= true  
                                Ok(())
                            }
                            else {
                                Err("The correct usage : 'enable id <ID>'".into())
                            } 
                        } else {
                            Err("The 'enable id <ID>' command is only available in VLAN Manager mode.".into())
                        }
                    },
                    "vlan_tagging" => {
                        if matches!(context.current_mode, Mode::VlanMode) {
                            println!("VLAN tagging enabled");
                            //Back-end implementation
                            //NetworkingManager.VlanManager.vlan[1].tagging.enabled=true 
                            Ok(())
                        } else {
                            Err("The 'enable vlan_tagging' command is only available in VLAN Manager mode.".into())
                        }
                    },
                    "vlan_routing" => {
                        if matches!(context.current_mode, Mode::VlanMode) {
                            if args.len() == 3 && args[1] == "id" {
                                let id = args[2];
                                println!("Enables the ID {}", id);
                                //Back-end implementation
                                //NetworkingManager.VlanManager.vlan[1].routing.enabled=true  
                                Ok(())
                            }
                            else {
                                Err("The correct usage : 'enable vlan_routing id <ID>'".into())
                            }
                        } else {
                            Err("The 'enable vlan_routing id <ID>' command is only available in VLAN Manager mode.".into())
                        }
                    },
                    "qos_config" => {
                        if matches!(context.current_mode, Mode::QosMode) {
                            println!("QOS config is enabled");
                            //Back-end implementation
                            //NetworkingManager.QosManager.QosConfiguration.enabled=true 
                            Ok(())
                        } else {
                            Err("The 'enable qos_config' command is only available in QOS Manager mode.".into())
                        }
                    },
                    _=> Err(format!("Unknown enable subcommand: {}", args[0]).into())
                }
            }
        },
    });

    //Enter the Global Configuration Mode
    commands.insert("config", Command {
        name: "configure network_manager",
        description: "Enter global configuration mode",
        suggestions: Some(vec!["network_manager", "vlan", "qos", "dynrouter", "portsec", "mon", "autod", "ospf", "rip"]),
        arg_suggest: Some(vec!["network_manager", "vlan", "qos", "dynrouter", "portsec", "mon", "autod", "ospf", "rip"]),
        suggestions1: None,
        suggestions2: None,
        options: None,
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::PrivilegedMode) {
                if args.len() == 1 && args[0] == "network_manager" {
                    context.current_mode = Mode::ConfigMode;
                    context.prompt = format!("{}(config)#", context.config.hostname);
                    println!("Enter configuration commands, one per line.  End with CNTL/Z");
                    Ok(())
                } else {
                    Err("Invalid arguments provided to 'configure terminal'. This command does not accept additional arguments.".into())
                }
            } else if !matches!(context.current_mode, Mode::UserMode | Mode::PrivilegedMode){
                if args.len() == 1 && args[0] == "vlan" {
                    context.current_mode = Mode::VlanMode;
                    context.prompt = format!("{}(config-Vlan)#", context.config.hostname);
                    println!("Enter Vlan Manager Mode for Vlan configurations");
                    Ok(())
                } else if args.len() == 1 && args[0] == "qos" {
                    context.current_mode = Mode::QosMode;
                    context.prompt = format!("{}(config-QOS)#", context.config.hostname);
                    println!("Enter QOS Manager Mode for QOS configurations");
                    Ok(())
                } else if args.len() == 1 && args[0] == "dynrouter" {
                    context.current_mode = Mode::DynamicRMode;
                    context.prompt = format!("{}(config-DynRouter)#", context.config.hostname);
                    println!("Enter Dynamic Routing Manager Mode for Dynamic Routing configurations");
                    Ok(())
                } else if args.len() == 1 && args[0] == "portsec" {
                    context.current_mode = Mode::PortSMode;
                    context.prompt = format!("{}(config-PortSec)#", context.config.hostname);
                    println!("Enter Port Security Manager Mode for Port Security configurations");
                    Ok(())
                } else if args.len() == 1 && args[0] == "mon" {
                    context.current_mode = Mode::MonitoringMode;
                    context.prompt = format!("{}(config-Mon)#", context.config.hostname);
                    println!("Enter Monitoring Manager Mode for Monitoring configurations");
                    Ok(())
                } else if args.len() == 1 && args[0] == "autod" {
                    context.current_mode = Mode::AutoDMode;
                    context.prompt = format!("{}(config-AutoD)#", context.config.hostname);
                    println!("Enter Auto Discovery Manager Mode for Auto Discovery configurations");
                    Ok(())
                }
                else if matches!(context.current_mode, Mode::DynamicRMode){
                    if args.len() == 1 && args[0] == "ospf" {
                        println!("OSPF Configuration is enabled.");
                        //Back-end implementation
                        Ok(())
                    } else if args.len() == 1 && args[0] == "rip" {
                        println!("RIP cconfiguration is enabled.");
                        //Back-end implementation
                        Ok(())
                    }
                    else {
                        Err("Invalid arguments provided to 'config commands'".into())
                    }
                }
                else {
                    Err("Invalid arguments provided to 'config commands'".into())
                }
            }
            else {
                Err("The 'config' commands are only available in Privileged EXEC mode and Config mode.".into())
            }
        },
    });

    //Enter the Interface Configuration Mode
    commands.insert("interface", Command {
        name: "interface",
        description: "Enter Interface configuration mode",
        suggestions: None,
        arg_suggest: None,
        suggestions1: None,
        suggestions2: Some(vec!["mode", "<enable|disable>", "<cpq|beq>"]),
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
            } else if matches!(context.current_mode, Mode::AutoDMode) {
                
                let (interface_list, interfaces_list) = match get_available_int() {
                    Ok(list) => list,
                    Err(e) => return Err(e),
                };
                
                //let args: Vec<String> = std::env::args().skip(1).collect();
                if args.is_empty() {
                    return Err(format!("Please specify a valid interface. Available interfaces: {}", interfaces_list));
                }
    
                if args.len() == 2 && (args[1] == "enable" || args[1] == "disable"){
                    let net_interface = &args[0];
                    if interface_list.iter().any(|i| i == net_interface) {
                        let status = args[1];
                        println!("Auto discovery {} for the interface {}", status, net_interface);
                        //NetworkingManager.AutoDiscoveryManager.interface[eth0]=false
                        Ok(())
                    } else {
                        Err(format!("Invalid interface: {}. Available interfaces: {}", net_interface, interfaces_list))
                    }
                } else if args.len() == 3 && args[1] == "mode" {
                    let net_interface = &args[0];
                    if interface_list.iter().any(|i| i == net_interface) {
                        let mode = args[2];
                        println!("Configure the mode {} for the interface {}", mode, net_interface);
                        //NetworkingManager.AutoDiscoveryManager.mode.interface[eth1]=transmit-only
                        Ok(())
                    } else {
                        Err(format!("Invalid interface: {}. Available interfaces: {}", net_interface, interfaces_list))
                    }
                } 
                else {
                    Err(format!("Invalid number of arguments.").into())
                }
            }
            else if matches!(context.current_mode, Mode::QosMode) {
                
                let (interface_list, interfaces_list) = match get_available_int() {
                    Ok(list) => list,
                    Err(e) => return Err(e),
                };
                
                //let args: Vec<String> = std::env::args().skip(1).collect();
                if args.is_empty() {
                    return Err(format!("Please specify a valid interface. Available interfaces: {}", interfaces_list));
                }
    
                if args.len() == 3 && (args[1] == "beq" || args[1] == "cpq") {
                    let net_interface = &args[0];
                    if interface_list.iter().any(|i| i == net_interface) {
                        if args[2] == "true" {
                            println!("Enables {} for the interface {}", args[1], net_interface);
                            //NetworkingManager.QosManager.QosConfiguration.interface[eth0].beq=true 
                            Ok(())
                        } else if args[2] == "false" {
                            println!("Disables {} for the interface {}", args[1], net_interface);
                            //NetworkingManager.QosManager.QosConfiguration.interface[eth0].beq=false
                            Ok(())
                        } else {
                            Err("Specify the condition as true or false. Command: 'interface <interface_name> [cpq|bed] [true|false]'".into())
                        }
                    } else {
                        Err(format!("Invalid interface: {}. Available interfaces: {}", net_interface, interfaces_list))
                    }
                }  
                else {
                    Err(format!("Invalid number of arguments.").into())
                }
            }
            
            else {
                Err("The 'interface' command is only available in Global Configuration, interface configuration mode and Auto Discovery Manager Mode.".into())
            }
        },
    });


    //Exit each and every mode and enter its parent mode
    commands.insert("exit", Command {
        name: "exit",
        description: "Exit the current mode and return to the previous mode.",
        suggestions: None,
        arg_suggest: None,
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
                    Mode::VlanMode => {
                        context.current_mode = Mode::ConfigMode;
                        context.prompt = format!("{}(config)#", context.config.hostname);
                        println!("Exiting Software and Database Management Mode...");
                        Ok(())
                    }
                    Mode::QosMode => {
                        context.current_mode = Mode::ConfigMode;
                        context.prompt = format!("{}(config)#", context.config.hostname);
                        println!("Exiting Built-In Test and Diagnostics Mode...");
                        Ok(())
                    }
                    Mode::DynamicRMode => {
                        context.current_mode = Mode::ConfigMode;
                        context.prompt = format!("{}(config)#", context.config.hostname);
                        println!("Exiting Position and Time Management Mode...");
                        Ok(())
                    }
                    Mode::PortSMode => {
                        context.current_mode = Mode::ConfigMode;
                        context.prompt = format!("{}(config)#", context.config.hostname);
                        println!("Exiting Radio Transmission Control Mode...");
                        Ok(())
                    }
                    Mode::MonitoringMode => {
                        context.current_mode = Mode::ConfigMode;
                        context.prompt = format!("{}(config)#", context.config.hostname);
                        println!("Exiting Information Distribution Mode...");
                        Ok(())
                    }
                    Mode::AutoDMode => {
                        context.current_mode = Mode::ConfigMode;
                        context.prompt = format!("{}(config)#", context.config.hostname);
                        println!("Exiting System Monitoring Mode...");
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
        suggestions: Some(vec!["network_manager", "vlan_manager", "qos_manager", "dynamic_routing_manager", "port_security_manager", "monitoring_manager", "auto_discovery_manager"]),
        arg_suggest: Some(vec!["network_manager", "vlan_manager", "qos_manager", "dynamic_routing_manager", "port_security_manager", "monitoring_manager", "auto_discovery_manager"]),
        suggestions1: None,
        suggestions2: None,
        options: None,
        execute: |args, context, _| {
            if args.is_empty() {
                match context.current_mode {
                    Mode::ConfigMode | Mode::InterfaceMode | Mode:: VlanMode | Mode:: QosMode | Mode:: DynamicRMode | Mode:: PortSMode | Mode:: MonitoringMode | Mode:: AutoDMode => {
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
            } else if args.len() == 1 {
                match &args[0][..]{
                    "network_manager" => {
                        if matches!(context.current_mode, Mode::ConfigMode) {
                            println!("Network Manager is disabled.");
                            //Back-end implementation
                            //NetworkingManager.enabled=false
                            Ok(())
                        } else {
                            Err("The 'disable network_manager' command is only available in Config mode.".into())
                        }
                    },
                    "vlan_manager" => {
                        if matches!(context.current_mode, Mode::VlanMode) {
                            println!("Vlan Manager is disabled.");
                            //Back-end implementation
                            //NetworkingManager.VlanManager.enabled=false
                            Ok(())
                        } else {
                            Err("The 'disable vlan_manager' command is only available in Vlan Manager mode.".into())
                        }
                    },
                    "qos_manager" => {
                        if matches!(context.current_mode, Mode::QosMode) {
                            println!("QOS Manager is disabled.");
                            //Back-end implementation
                            //NetworkingManager.QosManager.enabled=false
                            Ok(())
                        } else {
                            Err("The 'disable qos_manager' command is only available in QOS Manager mode.".into())
                        }
                    },
                    "dynamic_routing_manager" => {
                        if matches!(context.current_mode, Mode::DynamicRMode) {
                            if args.len() == 2 {  
                                let id = args[1];  
                                println!("Dynamic Routing Manager for the id {} is disabled.", id);
                                //Back-end implementation
                                //NetworkingManager.DynamicRoutingManager[id=2].enabled=false
                                Ok(())
                            } else{
                                Err("Correct usage: 'disable dynamic_routing_manager <ID>'".into())
                            }
                        } else {
                            Err("The 'disable dynamic_routing_manager <ID>' command is only available in Dynamic Routing Manager mode.".into())
                        }
                    },
                    "port_security_manager" => {
                        if matches!(context.current_mode, Mode::PortSMode) {
                            println!("Port Security Manager is disabled.");
                            //Back-end implementation
                            //NetworkingManager.PortSecurityManager.enabled=false
                            Ok(())
                        } else {
                            Err("The 'disable port_security_manager' command is only available in Port Security Manager mode.".into())
                        }
                    },
                    "monitoring_manager" => {
                        if matches!(context.current_mode, Mode::MonitoringMode) {
                            println!("Monitoring Manager is disabled.");
                            //Back-end implementation
                            //NetworkingManager.MonitoringManager.enabled=true 
                            Ok(())
                        } else {
                            Err("The 'disable monitoring_manager' command is only available in Monitoring Manager mode.".into())
                        }
                    },
                    "auto_discovery_manager" => {
                        if matches!(context.current_mode, Mode::AutoDMode) {
                            println!("Auto Discovery Manager is disabled.");
                            //Back-end implementation
                            //NetworkingManager.AutoDiscoveryManager.enabled=false
                            Ok(())
                        } else {
                            Err("The 'disable auto_discovery_manager' command is only available in Auto Discovery Manager mode.".into())
                        }
                    },
                    _=> Err(format!("Unknown enable subcommand: {}", args[0]).into())
                }
            }
            
            else {
                Err("Invalid arguments provided to 'exit'. This command does not accept additional arguments.".into())
            }
        },
    });

    //Reboot the system
    commands.insert("reload", Command {
        name: "reload",
        description: "Reload the system",
        suggestions: None,
        arg_suggest: None,
        suggestions1: None,
        suggestions2: None,
        options: None,
        execute: |_, _, _| {
    
            println!("Proceed with reload? [yes/no]:");
            let mut reload_confirm = String::new();
            std::io::stdin().read_line(&mut reload_confirm).expect("Failed to read input");
            let reload_confirm = reload_confirm.trim();
    
            if ["yes", "y", ""].contains(&reload_confirm.to_ascii_lowercase().as_str()) {
                if let Err(e) = execute_spawn_process("sudo", &["reboot"]) {
                    eprintln!("Failed to reboot: {}", e);
                }  
                
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
        arg_suggest: None,
        suggestions1: None,
        suggestions2: None,
        options: None,
        execute: |_, _, _| {
    
            println!("Do you want to shutdown the PC? [yes/no]:");
            let mut reload_confirm = String::new();
            std::io::stdin().read_line(&mut reload_confirm).expect("Failed to read input");
            let reload_confirm = reload_confirm.trim();
    
            if ["yes", "y", ""].contains(&reload_confirm.to_ascii_lowercase().as_str()) {
                let _ = fs::remove_file("history.txt");  
                if let Err(e) = execute_spawn_process("sudo", &["shutdown", "now"]) {
                    eprintln!("Failed to shutdown: {}", e);
                }
                
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
        arg_suggest: Some(vec!["all"]),
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
        arg_suggest: Some(vec!["all"]),
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
        arg_suggest: None,
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
            arg_suggest: None,
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
            arg_suggest: Some(vec![
                "running-config",
                "startup-config",
                "version",
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
                            let _ = show_sessions();
                            Ok(())
                        },

                        Some(&"controllers") if matches!(context.current_mode, Mode::UserMode) => {
                            
                            let _ = show_controllers();  
                            Ok(())
                        },
                        Some(&"history")  => {
                            let _ = show_history();
                            Ok(())
                        },
                        
                        Some(&"running-config") if matches!(context.current_mode, Mode::PrivilegedMode) => {
                            let _ = show_run_conf(&context);
                            Ok(())
                        },

                        Some(&"startup-config") if matches!(context.current_mode, Mode::PrivilegedMode) => {
                            let _ = show_start_conf(&context);
                            Ok(())
                        },

                        Some(&"interfaces") if matches!(context.current_mode, Mode::PrivilegedMode) => {
                            let _ = show_interfaces();
                            Ok(())
                        },

                        Some(&"ip") if matches!(context.current_mode, Mode::PrivilegedMode) => {
                            match args.get(1) {
                                Some(&"interface") => {
                                    match args.get(2) {
                                        Some(&"brief") => {
                                            let _ = show_ip_int_br();
                                            Ok(())
                                        },
                                        Some(&interface) => {
                                            // Verify the interface exists before showing its details
                                            match get_available_int() {
                                                Ok((interface_list, _)) => {
                                                    if interface_list.iter().any(|i| i == interface) {
                                                        let _ = show_ip_int_sp(interface)?;
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
                                    let _ = show_ip_route();
                                    Ok(())
                                }
                                _ => Err("Invalid IP subcommand. Use 'interface brief'".into())
                            }
                        },

                        Some(&"login") if matches!(context.current_mode, Mode::PrivilegedMode) => {
                            let _ = show_login();
                            Ok(())
                        },                        
                    
                        Some(&"processes") if matches!(context.current_mode, Mode::PrivilegedMode) => {
                            let _ = show_proc();
                            Ok(())
                            
                            
                        },
                        Some(&"arp") => {
                            let _ = show_arp();
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
            suggestions: Some(vec!["show", "copy", "clock", "debug", "undebug"]),
            arg_suggest: Some(vec!["show", "copy", "clock", "debug", "undebug"]),
            suggestions1: Some(vec!["show", "copy", "clock", "debug", "undebug"]),
            suggestions2: Some(vec![
                "running-config",
                "startup-config",
                "version",
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
                                let _ = show_sessions();
                                Ok(())
                            },
                            Some(&"controllers") => {
                                let _ = show_controllers();                                
                                Ok(())
                            },
                            Some(&"history") => {
                                let _ = show_history();
                                Ok(())
                            },
                            Some(&"running-config") => {
                                let _ = show_run_conf(&context);
                                Ok(())
                            },
                            Some(&"startup-config") => {
                                let _ = show_start_conf(&context);
                                Ok(())
                            },
                            Some(&"interfaces") => {
                                let _ = show_interfaces();
                                Ok(())
                            },
                            Some(&"ip") => {
                                match args.get(2) {
                                    Some(&"interface") => {
                                        match args.get(3) {
                                            Some(&"brief") => {
                                                let _ = show_ip_int_br();
                                                Ok(())
                                            },
                                            Some(&interface) => {
                                                // Verify the interface exists before showing its details
                                                match get_available_int() {
                                                    Ok((interface_list, _)) => {
                                                        if interface_list.iter().any(|i| i == interface) {
                                                            let _ = show_ip_int_sp(interface)?;
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
                                        let _ = show_ip_route();
                                        Ok(())
                                    }
                                    _ => Err("Invalid IP subcommand. Use 'interface brief'".into())
                                }
                            },
                            Some(&"login") => {
                                let _ = show_login();
                                Ok(())
                            },
                            Some(&"processes") => {
                                let _ = show_proc();
                                Ok(())
                            },
                            Some(&"arp") => {
                                let _ = show_arp();
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
                            
                                        let _ = handle_clock_set(time, day, month, year, clock);
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
            arg_suggest: Some(vec!["memory"]),
            suggestions1: Some(vec!["memory"]),
            suggestions2: None,
            options: None,
            execute: |args, context, _| {
                if matches!(context.current_mode, Mode::UserMode | Mode::PrivilegedMode | Mode::ConfigMode) {
                    if args.len() == 1 && args[0] == "memory" {
                        let _ = save_running_to_startup(context);
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
            arg_suggest: Some(vec!["running-config"]),
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
            arg_suggest: None,
            suggestions1: None,
            suggestions2: None,
            options: None,
            execute: |_args, context, _| {
                help_command(&context);
                Ok(())
            }
        },
    );

    //Assign IP addresses for interfaces and define IP routes
    commands.insert(
        "ip",
        Command {
            name: "ip",
            description: "Define all the ip commands",
            suggestions: Some(vec!["address", "route"]),
            arg_suggest: Some(vec!["address", "route"]),
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
            arg_suggest: None,
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
            suggestions: Some(vec!["shutdown", "ip"]),
            arg_suggest: Some(vec!["shutdown", "ip"]),
            suggestions1: Some(vec!["shutdown", "ip"]),
            suggestions2: Some(vec!["route"]),
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
        suggestions: None,
        arg_suggest: None,
        suggestions1: None,
        suggestions2: None,
        options: None,
        execute: |args, _context, _| {
            match args.get(0) {
                None => {
                    ProcessCommand::new("clear")
                        .status()
                        .unwrap();
                    Ok(())
                },
                
                _ => Err("Invalid command. Available commands: clear, clear ntp associations".into())
            }
        },
    });

    
    //Encrypt the passwords
    commands.insert("service", Command {
        name: "service password-encryption",
        description: "Enable password encryption",
        suggestions: Some(vec!["password-encryption"]),
        arg_suggest: Some(vec!["password-encryption"]),
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
            arg_suggest: Some(vec![
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
            execute: |args, _context, _| {
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
        arg_suggest: None,
        suggestions1: None,
        suggestions2: None,
        options: None, 
        execute: |_args, _context, _| {
           
            if let Err(e) = execute_spawn_process("sudo", &["dhclient", "-r"]) {
                eprintln!("Failed to release DHCP: {}", e);
            } else {
                println!("Removed existing DHCP configurations");
            }
            
            if let Err(e) = execute_spawn_process("sudo", &["dhclient"]) {
                eprintln!("Failed to enable DHCP: {}", e);
            } else {
                println!("Enabled DHCP configurations");
            }
            
            if let Err(e) = execute_spawn_process("sudo", &["systemctl", "restart", "NetworkManager"]) {
                eprintln!("Failed to restart network services: {}", e);
            } else {
                println!("Restarted network services");
            }
            
            Ok(())

        },
    });


    //ping command
    commands.insert("ping", Command {
        name: "ping",
        description: "Ping a specific IP address to check reachability",
        suggestions: None,
        arg_suggest: None,
        suggestions1: None,
        suggestions2: None,
        options: Some(vec!["<ip-address>    - Enter the ip-address"]),
        execute: |args, _context, _| {
            if args.len() == 1 {
                let ip = args[0].to_string();
                
                println!("Pinging {} with 32 bytes of data:", ip);
                if let Err(e) = execute_spawn_process("ping", &["-c", "4", "-s", "32", &ip]) {
                    eprintln!("Failed to ping: {}", e);
                }
                
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
        arg_suggest: None,
        suggestions1: None,
        suggestions2: None,
        options: Some(vec!["<ip-address/hostname>    - Enter the IP address or hostname"]),
        execute: |args, _context, _| {
            if args.len() == 1 {
                let target = args[0].to_string();
    
                println!("Tracing route to {} over a maximum of 30 hops", target);
                if let Err(e) = execute_spawn_process("traceroute", &["-n", "-m", "30", &target]) {
                    eprintln!("Failed to traceroue: {}", e);
                }
                
                println!("Trace Completed.");
                Ok(())

            } else {
                Err("Invalid syntax. Usage: traceroute <ip/hostname>".into())
            }
        },
    });

    // Dynamic Router Manager Mode Commands

    commands.insert("network", Command {
        name: "network",
        description: "Configure the network commands",
        suggestions: None,
        arg_suggest: None,
        suggestions1: None,
        suggestions2: Some(vec!["ip", "area", "netmask"]),
        options: Some(vec!["<interface>         - Mention the interface"]),
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::DynamicRMode) {
                if args.len() == 3 && args[1] == "ip" {
                    let interface = args[0];
                    let ip_address = args[2];
                    //NetworkingManager.DynamicRoutingManager.OspfConfiguration.interface[eth0].ipaddr=10.0.0.1 
                    println!("Configuring the interface {} the ip address of {} of the ospf feature", interface, ip_address);
                    Ok(())
                } else if args.len() == 3 && args[1] == "netmask" {
                    let interface = args[0];
                    let netmask = args[2];
                    //NetworkingManager.DynamicRoutingManager.OspfConfiguration.interface[eth0].ipmask=255.255.255.0 
                    println!("Configuring the interface {} netmask as {} of the ospf feature", interface, netmask);
                    Ok(())
                } else if args.len() == 3 && args[1] == "area" {
                    let interface = args[0];
                    let area = args[2];
                    //NetworkingManager.DynamicRoutingManager.OspfConfiguration.interface[eth0].area=0.0.0.0 
                    println!("Configuring the interface {} the area {} of the ospf feature", interface, area);
                    Ok(())
                }
                else {
                    Err("Invalid arguments for 'network' command".into())
                }
            } else {
                Err("The 'network' command is only available in Dynamic Routing Manager Mode.".into())
            }
        },
    });

    commands.insert("redistribute", Command {
        name: "redistribute ospf and rip",
        description: "redistribute ospf and rip",
        suggestions: Some(vec!["rip", "ospf"]),
        arg_suggest: Some(vec!["rip", "ospf"]),
        suggestions1: Some(vec!["rip", "ospf"]),
        suggestions2: None,
        options: None,
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::DynamicRMode) {
                if args.len() == 1 && args[0] == "ospf" {
                    //NetworkingManager.DynamicRoutingManager.OspfConfiguration.redistribute=true 
                    println!("Configuring redistribution capability of the OSPF feature");
                    Ok(())
                } else if args.len() == 1 && args[0] == "rip" {
                    //NetworkingManager.DynamicRoutingManager.RipConfiguration.redistribute=true 
                    println!("Configuring redistribution capability of the RIP feature");
                    Ok(())
                } 
                else {
                    Err("Invalid arguments for 'redistribute' command. 'redistribute [ospf|rip]'".into())
                }
            } else {
                Err("The 'redistribute'' command is only available in Dynamic Routing Manager Mode.".into())
            }
        },
    });

    commands.insert("valid", Command {
        name: "valid ospf and rip",
        description: "valid ospf and rip",
        suggestions: Some(vec!["rip", "ospf"]),
        arg_suggest: Some(vec!["rip", "ospf"]),
        suggestions1: Some(vec!["rip", "ospf"]),
        suggestions2: None,
        options: None,
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::DynamicRMode) {
                if args.len() == 1 && args[0] == "ospf" {
                    //NetworkingManager.DynamicRoutingManager.OspfConfiguration.status=valid 
                    println!("Writing the previous configuration to the OSPF manager");
                    Ok(())
                } else if args.len() == 1 && args[0] == "rip" {
                    //NetworkingManager.DynamicRoutingManager.RipConfiguration.status=valid 
                    println!("Writing the previous configuration to the RIP manager");
                    Ok(())
                } 
                else {
                    Err("Invalid arguments for 'valid' command. 'valid [ospf|rip]'".into())
                }
            } else {
                Err("The 'valid'' command is only available in Dynamic Routing Manager Mode.".into())
            }
        },
    });

    commands.insert("controller", Command {
        name: "controller status",
        description: "Define controller status",
        suggestions: Some(vec!["status"]),
        arg_suggest: Some(vec!["status"]),
        suggestions1: Some(vec!["status"]),
        suggestions2: None,
        options: Some(vec!["<status>        - Define the controller status"]),
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::DynamicRMode) {
                if args.len() == 2 && args[0] == "status" {
                    let status = args[1];
                    //NetworkingManager.DynamicRoutingManager.RipController.rip.status=running  
                    println!("Controller status set the {}", status);
                    Ok(())
                } 
                else {
                    Err("Invalid arguments for 'controller' command. 'controller status <status>'".into())
                }
            } else {
                Err("The 'controller'' command is only available in Dynamic Routing Manager Mode.".into())
            }
        },
    });

    //VLAN Manager Mode commands

    commands.insert("bridge_name", Command {
        name: "bridge_name",
        description: "Configures the name of a bridge ",
        suggestions: None,
        arg_suggest: None,
        suggestions1: None,
        suggestions2: None,
        options: Some(vec!["<name>        - Define the bridge name"]),
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::VlanMode) {
                if args.len() == 1 {
                    let name = args[0];
                    //NetworkingManager.VlanManager.bridge.name=’bridge1’
                    println!("Bridge name is set to {}", name);
                    Ok(())
                } 
                else {
                    Err("Invalid arguments for 'bridge_name' command. 'bridge_name <name>'".into())
                }
            } else {
                Err("The 'bridge_name' command is only available in VLAN Manager Mode.".into())
            }
        },
    });

    commands.insert("add", Command {
        name: "add bridge and interface",
        description: "Adds the bridge and interface ",
        suggestions: Some(vec!["bridge", "interface"]),
        arg_suggest: Some(vec!["bridge", "interface"]),
        suggestions1: Some(vec!["bridge", "interface"]),
        suggestions2: None,
        options: Some(vec!["<name>        - Define the specified name"]),
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::VlanMode) {
                if args.len() == 4 && args[0] == "bridge" && args[2] == "interface"{
                    let b_name = args[1];
                    let i_name = args[3];
                    //NetworkingManager.VlanManager.bridge[bridge1].interface[eth0].add=true
                    println!("The bridge {} is added to the interface {}", b_name, i_name);
                    Ok(())
                } 
                else if args.len() == 6 && args[0] == "interface" && args[2] == "protocol" && args[4] == "router" {
                    let i_name = args[1];
                    let protocol = args[3];
                    let r_name = args[5];
                    //NetworkingManager.VlanManager.router[router1].protocol[‘ospf].interface[eth1].add=true 
                    println!("{} routing protocol is added to the interface {} and router {}", protocol, i_name, r_name);
                    Ok(())
                } 
                else {
                    Err("Invalid arguments for 'add' command.".into())
                }
            } else {
                Err("The 'add' command is only available in VLAN Manager Mode.".into())
            }
        },
    });

    commands.insert("router", Command {
        name: "router name",
        description: "Configures the name of a router (router1)",
        suggestions: Some(vec!["name"]),
        arg_suggest: Some(vec!["name"]),
        suggestions1: Some(vec!["name"]),
        suggestions2: None,
        options: Some(vec!["<name>        - Define the router name"]),
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::VlanMode) {
                if args.len() == 2 {
                    let name = args[1];
                    //NetworkingManager.VlanManager.router.name=’router1’ 
                    println!("Router name is set to {}", name);
                    Ok(())
                } 
                else {
                    Err("Invalid arguments for 'router' command. 'router name <name>'".into())
                }
            } else {
                Err("The 'router name' command is only available in VLAN Manager Mode.".into())
            }
        },
    });

    commands.insert("segment", Command {
        name: "segment id",
        description: "Configures VLAN segment ID ",
        suggestions: Some(vec!["id"]),
        arg_suggest: Some(vec!["id"]),
        suggestions1: Some(vec!["id"]),
        suggestions2: None,
        options: Some(vec!["<ID>        - Define the ID"]),
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::VlanMode) {
                if args.len() == 2 {
                    let id = args[1];
                    //NetworkingManager.VlanManager.vlan.segment.id=1 
                    println!("Segment ID is set to {}", id);
                    Ok(())
                } 
                else {
                    Err("Invalid arguments for 'segment id' command. 'segment id <ID>'".into())
                }
            } else {
                Err("The 'segment id' command is only available in VLAN Manager Mode.".into())
            }
        },
    });

    commands.insert("vlan", Command {
        name: "vlan id",
        description: "Assigns VLAN ID",
        suggestions: Some(vec!["id"]),
        arg_suggest: Some(vec!["id"]),
        suggestions1: Some(vec!["id"]),
        suggestions2: None,
        options: Some(vec!["<ID>        - Define the ID"]),
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::VlanMode) {
                if args.len() == 2 {
                    let id = args[1];
                    //NetworkingManager.VlanManager.vlan[1].id= 2 
                    println!("VLAN ID is set to {}", id);
                    Ok(())
                } 
                else {
                    Err("Invalid arguments for 'vlan id' command. 'vlan id <ID>'".into())
                }
            } else {
                Err("The 'vlan id' command is only available in VLAN Manager Mode.".into())
            }
        },
    });

    //QOS Manager Mode Commands

    commands.insert("policy", Command {
        name: "policy",
        description: "Sets the QoS policy",
        suggestions: None,
        arg_suggest: None,
        suggestions1: None,
        suggestions2: None,
        options: Some(vec!["<policy>        - Set the QOS policy"]),
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::QosMode) {
                if args.len() == 1 {
                    let policy = args[0];
                    //NetworkingManager.QosManager.QosConfiguration.policy=’equal-acrossinterfaces’
                    println!("QOS policy is set to {}", policy);
                    Ok(())
                } 
                else {
                    Err("Invalid arguments for 'policy' command. 'policy <policy>'".into())
                }
            } else {
                Err("The 'policy' command is only available in QOS Manager Mode.".into())
            }
        },
    });

    commands.insert("priority", Command {
        name: "priority",
        description: "Assigns priority level to an interface",
        suggestions: Some(vec!["level"]),
        arg_suggest: Some(vec!["level"]),
        suggestions1: Some(vec!["level"]),
        suggestions2: None,
        options: Some(vec!["<level>        - Set the priority level"]),
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::QosMode) {
                if args.len() == 4 && args[0] == "level" && args[2] == "interface" {
                    let level = args[1];
                    let interface = args[3];
                    //NetworkingManager.QosManager.QosConfiguration.interface[eth0].priority[1]=true  
                    println!("Priority level {} is set to the interface {}", level, interface);
                    Ok(())
                } 
                else {
                    Err("Invalid arguments for 'priority' command. 'priority level <level> interface <interface_name> '".into())
                }
            } else {
                Err("The 'priority' command is only available in QOS Manager Mode.".into())
            }
        },
    });

    //Port Security Manager Mode

    commands.insert("mode", Command {
        name: "mode",
        description: "Sets the port security mode to static",
        suggestions: None,
        arg_suggest: None,
        suggestions1: None,
        suggestions2: None,
        options: Some(vec!["<mode>        - Set the mode"]),
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::PortSMode) {
                if args.len() == 1 {
                    let mode = args[0];
                    //NetworkingManager.PortSecurityManager.mode=’static’ 
                    println!("Port security mode set to {}", mode);
                    Ok(())
                } 
                else {
                    Err("Invalid arguments for 'mode' command. 'mode <mode>'".into())
                }
            } else {
                Err("The 'mode' command is only available in Port Security Manager Mode.".into())
            }
        },
    });

    commands.insert("max_devices", Command {
        name: "max_devices",
        description: "Limits the maximum number of devices allowed per port to 2. ",
        suggestions: None,
        arg_suggest: None,
        suggestions1: None,
        suggestions2: None,
        options: Some(vec!["<number>        - Set the maximum amount of number of devices"]),
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::PortSMode) {
                if args.len() == 1 {
                    let number = args[0];
                    //NetworkingManager.PortSecurityManager.static.MaxDevices= 2 
                    println!("The maximum amount of devices set to {}", number);
                    Ok(())
                } 
                else {
                    Err("Invalid arguments for 'max_devices' command. 'max_devices <number>'".into())
                }
            } else {
                Err("The 'max_devices' command is only available in Port Security Manager Mode.".into())
            }
        },
    });

    commands.insert("violation_status", Command {
        name: "violation_status",
        description: "Configures the violation mode to restrict, allowing monitoring and logging of security violations while restricting unauthorized devices.",
        suggestions: None,
        arg_suggest: None,
        suggestions1: None,
        suggestions2: None,
        options: Some(vec!["<status>        - Set the status"]),
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::PortSMode) {
                if args.len() == 1 {
                    let status = args[0];
                    //NetworkingManager.PortSecurityManager.static.violation=’restrict’ 
                    println!("The violation status is set to {}", status);
                    Ok(())
                } 
                else {
                    Err("Invalid arguments for 'violation_status' command. 'violation_status <status>'".into())
                }
            } else {
                Err("The 'violation_status' command is only available in Port Security Manager Mode.".into())
            }
        },
    });

    //Monitoring Manager Mode

    commands.insert("logging_level", Command {
        name: "logging_level",
        description: "Define logging level",
        suggestions: None,
        arg_suggest: None,
        suggestions1: None,
        suggestions2: None,
        options: Some(vec!["<level>        - Define the logging level"]),
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::MonitoringMode) {
                if args.len() == 1 {
                    let level = args[0];
                    //NetworkingManager.MonitoringManager.logging=’info’   
                    println!("Logging level set to {}", level);
                    Ok(())
                } 
                else {
                    Err("Invalid arguments for 'logging_level' command. 'logging_level <level>'".into())
                }
            } else {
                Err("The 'logging_level' command is only available in Monitoring Manager Mode.".into())
            }
        },
    });

    //Auto Discovery Manager Mode
    
    commands.insert("holdtime", Command {
        name: "holdtime",
        description: "Sets the hold time for discovery messages to the default value.",
        suggestions: None,
        arg_suggest: None,
        suggestions1: None,
        suggestions2: None,
        options: Some(vec!["<time|default>        - Set the hold time in seconds"]),
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::AutoDMode) {
                if args.len() == 1 {
                    let time = args[0];
                    //NetworkingManager.AutoDiscoveryManager.holdtime=default 
                    println!("Holt time set to {}s", time);
                    Ok(())
                } 
                else {
                    Err("Invalid arguments for 'holdtime' command. 'holdtime <time|default>'".into())
                }
            } else {
                Err("The 'holdtime' command is only available in Auto Discovery Manager Mode.".into())
            }
        },
    });

    commands.insert("reinit", Command {
        name: "Reinit",
        description: "Sets the reinitialization behavior to the default setting. ",
        suggestions: Some(vec!["behaviour"]),
        arg_suggest: Some(vec!["behaviour"]),
        suggestions1: Some(vec!["behaviour"]),
        suggestions2: None,
        options: Some(vec!["<behaviour>        - Define the reinitialization behaviour"]),
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::AutoDMode) {
                if args.len() == 2 {
                    let behaviour = args[1];
                    //NetworkingManager.AutoDiscoveryManager.reinit=default   
                    println!("Reinitialization behaviour set to {}", behaviour);
                    Ok(())
                } 
                else {
                    Err("Invalid arguments for 'reinit' command. 'reinit behaviour <behaviour>'".into())
                }
            } else {
                Err("The 'reinit' command is only available in Auto Discovery Manager Mode.".into())
            }
        },
    });

    commands
}


fn copy_run_config(running_config: &str, destination: &str, context: &mut CliContext) -> Result<(), String> {
    if destination == "startup-config" {
        let _ = save_running_to_startup(context);
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