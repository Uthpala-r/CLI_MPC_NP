/// External crates for the CLI application
use std::net::Ipv4Addr;
use std::sync::{Mutex, Arc};
use std::collections::HashMap;
use std::process::Command as ProcessCommand;
use std::process::Stdio;
use std::path::Path;
use std::io::{self, BufRead, BufReader};
use std::fs::File;
use std::str::FromStr;

lazy_static::lazy_static! {

    pub static ref SELECTED_INTERFACE: Mutex<Option<String>> = Mutex::new(None);

    pub static ref STATUS_MAP: Arc<Mutex<HashMap<String, bool>>> = Arc::new(Mutex::new({
        let mut map = HashMap::new();
    
        // Default interface status (administratively down)
        map.insert("ens33".to_string(), false); // Modify as per your setup
    
        map
    }));

    pub static ref IP_ADDRESS_STATE: Mutex<HashMap<String, (Ipv4Addr, Ipv4Addr)>> = Mutex::new(HashMap::new());

    pub static ref ROUTE_TABLE: Mutex<HashMap<String, (Ipv4Addr, String)>> = Mutex::new(HashMap::new());

}


pub fn get_system_interfaces(interface: Option<&str>) -> String {
    let output = ProcessCommand::new("ifconfig")
        .args(interface)
        .output()
        .unwrap_or_else(|_| {
            // Try with /sbin/ifconfig if regular ifconfig fails
            ProcessCommand::new("/sbin/ifconfig")
                .args(interface)
                .output()
                .unwrap_or_else(|_| panic!("Failed to execute ifconfig"))
        });
    
    let output_str = String::from_utf8_lossy(&output.stdout).to_string();
    
    // If no specific interface was requested, return all interfaces
    if interface.is_none() {
        return output_str;
    }
    
    output_str
}

/// Represents the NTP (Network Time Protocol) association details for a device.
/// 
/// This structure holds information related to the NTP association, such as the server's
/// address, reference clock, synchronization status, and time offset values.
#[derive(Default, Clone)]
pub struct NtpAssociation {
    pub address: String,
    pub ref_clock: String,
    pub st: u8,
    pub when: String,
    pub poll: u8,
    pub reach: u8,
    pub delay: f64,
    pub offset: f64,
    pub disp: f64,
}

pub fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where P: AsRef<Path> {
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}

pub fn connect_via_ssh(hostname: &str, ip: &str) -> Result<(), String> {
    // Validate the IP address
    match Ipv4Addr::from_str(ip) {
        Ok(_) => {
            // IP address is valid, proceed with SSH connection
            let ssh_target = format!("{}@{}", hostname, ip);
            let status = ProcessCommand::new("ssh")
                .args([
                    "-o", "StrictHostKeyChecking=no",
                    "-o", "UserKnownHostsFile=/dev/null",
                    &ssh_target,
                ])
                .status()
                .map_err(|e| format!("Failed to execute SSH command: {}", e))?;
            
            if status.success() {
                Ok(())
            } else {
                Err(format!("SSH connection to {} failed with status: {}", ssh_target, status))
            }
        },
        Err(_) => Err(format!("Invalid IP address: {}", ip)),
    }
}

pub fn execute_spawn_process(command: &str, args: &[&str]) -> Result<(), String> {
    let mut child = match ProcessCommand::new(command)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(e) => return Err(format!("Failed to execute {}: {}", command, e)),
    };

    // Read stdout line by line
    if let Some(stdout) = child.stdout.take() {
        let reader = BufReader::new(stdout);
        for line in reader.lines() {
            match line {
                Ok(l) => println!("{}", l),
                Err(_) => println!("Error reading output"),
            }
        }
    }

    // Wait for the process to finish
    let status = match child.wait() {
        Ok(status) => status,
        Err(e) => return Err(format!("Failed to wait for {} process: {}", command, e)),
    };

    if status.success() {
        Ok(())
    } else {
        Err(format!("{} command failed with exit status: {}", command, status))
    }
}


pub fn ip_with_cidr(ip: &str, subnet_mask: &str) -> Result<String, String> {
    let mask_octets: Vec<u8> = subnet_mask
        .split('.')
        .map(|s| s.parse::<u8>().unwrap_or(0))
        .collect();

    if mask_octets.len() != 4 {
        return Err("Invalid subnet mask".to_string());
    }

    let cidr_prefix = mask_octets.iter().map(|&octet| octet.count_ones()).sum::<u32>();

    Ok(format!("{}/{}", ip, cidr_prefix))
}

pub fn get_available_int() -> Result<(Vec<String>, String), String> {
    let interfaces_output = std::fs::read_dir("/sys/class/net");
                
    // Create the interface_list from the filesystem entries
    let interface_list = match interfaces_output {
        Ok(entries) => {
            entries
                .filter_map(|entry| {
                    entry.ok().and_then(|e| 
                        e.file_name().into_string().ok()
                    )
                })
                .collect::<Vec<String>>()
        },
        Err(e) => return Err(format!("Failed to read network interfaces: {}", e))
    };
    
    // Generate comma-separated list for display
    let interfaces_list = interface_list.join(", ");
    Ok((interface_list, interfaces_list))
}

pub fn terminate_ssh_session() {
    // First attempt to kill the SSH process directly
    if let Ok(output) = ProcessCommand::new("sh")
        .arg("-c")
        .arg("ps -p $PPID -o ppid=")
        .output()
    {
        if let Ok(ppid) = String::from_utf8(output.stdout)
            .unwrap_or_default()
            .trim()
            .parse::<i32>() 
        {
            // Kill the parent SSH process
            let _ = ProcessCommand::new("kill")
                .arg("-9")
                .arg(ppid.to_string())
                .output();
        }
    }

    // As a fallback, try to terminate the session using multiple methods
    let cleanup_commands = [
        "exit",
        "logout",
        "kill -9 $PPID",  // Kill parent process
    ];

    for cmd in cleanup_commands.iter() {
        let _ = ProcessCommand::new("sh")
            .arg("-c")
            .arg(cmd)
            .status();
    }

    // Finally, force exit this process
    std::process::exit(0);
}