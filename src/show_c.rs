use crate::cliconfig::CliContext;
use crate::network_config::{read_lines, execute_spawn_process};
use crate::run_config::{get_running_config};

pub fn show_clock() -> Result<(), String> {
    if let Err(e) = execute_spawn_process("date", &["-u"]) {
        eprintln!("Failed to show the uptime: {}", e);
    }
    Ok(())
}

pub fn show_uptime() -> Result<(), String> {
    if let Err(e) = execute_spawn_process("uptime", &[]) {
        eprintln!("Failed to show the uptime: {}", e);
    }
    Ok(())
}

pub fn show_version() {
    //Acess a version file and show
    println!("PNF_MPC_CLI_Version --> '1.0.0'");
}

pub fn show_sessions() -> Result<(), String> {
    //Use 'w' command to access the system Telnet sessions
    if let Err(e) = execute_spawn_process("ps", &[]) {
        eprintln!("Failed to execute the sessions: {}", e);
    }
    
    Ok(())
}

pub fn show_controllers() -> Result<(), String> {
    
    //Triggers the command ‘lspci’ or ‘sudo lshw -class network’ and extract the relevant details.
    println!("USB Controllers");
    if let Err(e) = execute_spawn_process("lsusb", &[]) {
        eprintln!("Failed to show usb controllers: {}", e);
    } 
    println!("");
    println!("PCI Controllers");
    if let Err(e) = execute_spawn_process("lspci", &[]) {
        eprintln!("Failed to show pcicontrollers: {}", e);
    }
    
    Ok(())
}


pub fn show_history() -> Result<(), String>{
    // Read from history.txt file
                            
    match read_lines("history.txt") {
        Ok(lines) => {
            for line in lines.flatten() {
                println!("{}", line);
            }
            Ok(())
        },
        Err(e) => Err(format!("Error reading history file: {}", e).into())
    }
}

pub fn show_run_conf(context: &CliContext) -> Result<(), String>{
    println!("Building configuration...\n");
    println!("Current configuration : 0 bytes\n");
    let running_config = get_running_config(&context);
    println!("{}", running_config);
    Ok(())
}

pub fn show_start_conf(context: &CliContext) -> Result<(), String> {
    println!("Reading startup configuration file...\n");
    
    let config_path = "startup-config.conf";
    
    match std::fs::read_to_string(config_path) {
        Ok(contents) => {
            if let Some(last_written) = &context.config.last_written {
                println!("Startup configuration (last saved: {}):\n", last_written);
            } else {
                println!("Startup configuration file contents:\n");
            }
            println!("{}", contents);
        },
        Err(e) => {
            return Err(format!("Error reading startup configuration file: {}", e));
        }
    }
    
    Ok(())
}

pub fn show_interfaces() -> Result<(), String> {
    
    //Use ls /sys/class/net command
    if let Err(e) = execute_spawn_process("ip", &["link", "show"]) {
        eprintln!("Failed to show interfaces: {}", e);
    }
    
    Ok(())
                    
}

pub fn show_ip_int_br() -> Result<(), String> {
    if let Err(e) = execute_spawn_process("ip", &["a"]) {
        eprintln!("Failed to show interfaces in brief: {}", e);
    }
    
    Ok(())
}

pub fn show_ip_int_sp(interface: &str) -> Result<(), String> {
    execute_spawn_process("ifconfig", &[interface])
        .map_err(|e| format!("Failed to show interface details: {}", e))?;
    Ok(())
}

pub fn show_ip_route() -> Result<(), String> {
    if let Err(e) = execute_spawn_process("ip", &["route"]) {
        eprintln!("Failed to show ip routes: {}", e);
    }
    
    Ok(())
}

pub fn show_login() -> Result<(), String> {
    
    //Triggers the system ‘last’ and ‘faillog’ commands.
    if let Err(e) = execute_spawn_process("id", &[]) {
        eprintln!("Failed to show logins: {}", e);
    }
    
    Ok(())
}


pub fn show_proc() -> Result<(), String> {
    //Triggers the system commands (eg. Top, lscpu) and display the output 
    if let Err(e) = execute_spawn_process("cat", &["/proc/cpuinfo"]) {
        eprintln!("Failed to show processors: {}", e);
    }
    Ok(()) 
}

pub fn show_arp() -> Result<(), String> {
    //Use 'w' command to access the system Telnet sessions
    if let Err(e) = execute_spawn_process("ip", &["neigh"]) {
        eprintln!("Failed to show arp tables: {}", e);
    }
    
    Ok(())
}