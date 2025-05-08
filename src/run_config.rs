/// External crates for the CLI application
use crate::cliconfig::{CliContext};
use crate::execute::Mode;
use crate::network_config::{STATUS_MAP, IP_ADDRESS_STATE, ROUTE_TABLE};


pub fn save_running_to_startup(context: &CliContext) -> Result<(), String> {
    println!("Saving running configuration to startup-config.conf...");
 
    let running_config = get_running_config(context);
    let config_path = "startup-config.conf";

    match std::fs::write(config_path, running_config) {
        Ok(_) => {
            println!("Running configuration successfully saved to startup-config.conf");
            Ok(())
        },
        Err(e) => {
            Err(format!("Error writing to startup configuration file: {}", e))
        }
    }
}


/// Retrieves the current running configuration of the device.
/// 
/// The running configuration is a volatile piece of information that reflects 
/// the current state of the device, including any changes made to it. This 
/// configuration is stored in memory rather than NVRAM, meaning it will be lost 
/// when the device loses power.
/// 
/// # Returns
/// A `String` representing the current running configuration of the device.
/// 
/// # Example
/// ```rust
/// let config = get_running_config();
/// println!("Running Configuration: {}", config);
/// ``` 
pub fn get_running_config(context: &CliContext) -> String {
    let hostname = &context.config.hostname;
    let encrypted_password = context.config.encrypted_password.clone().unwrap_or_default();
    let encrypted_secret = context.config.encrypted_secret.clone().unwrap_or_default();
    
    // Access global states
    let ip_address_state = IP_ADDRESS_STATE.lock().unwrap();
    let status_map = STATUS_MAP.lock().unwrap();
    let route_table = ROUTE_TABLE.lock().unwrap();

    let interface = context
        .selected_interface
        .clone()
        .unwrap_or_else(|| "FastEthernet0/1".to_string());

    let ip_address = ip_address_state
        .get(&interface)
        .map(|(ip, _)| ip.to_string())
        .unwrap_or_else(|| "no ip address".to_string());
    
    let mut route_entries = String::new();
    for (destination, (netmask, next_hop_or_iface)) in route_table.iter() {
        route_entries.push_str(&format!(
            "ip route {} {} {}\n",
            destination, netmask, next_hop_or_iface
        ));
    }

    let shutdown_status = if status_map.get(&interface).copied().unwrap_or(false) {
        "no shutdown"
    } else {
        "shutdown"
    };

    
    format!(
        r#"version 15.1
no service timestamps log datetime msec
{}
!
hostname {}
!
enable password 5 {}
enable secret 5 {}
!
interface {}
 ip address {}
 duplex auto
 speed auto
 {}
!
interface Vlan1
 no ip address
 shutdown
!

ip classes
{}
!
router ospf 
 log-adjacency-changes
 passive-interface 
 
!

!
!
end
"#,
        if context.config.password_encryption {
            "service password-encryption"
        } else {
            "no service password-encryption"
        },
        hostname,
        encrypted_password,
        encrypted_secret,
        interface,
        ip_address,
        shutdown_status,
        route_entries,
        
    )
}


pub fn help_command(context: &CliContext){
    println!("\n ");
                println!(r#"Help may be requested at any point in a command by entering
a question mark '?'. If nothing matches, the help list will
be empty and you must backup until entering a '?' shows the
available options.
Two styles of help are provided:
1. Full help is available when you are ready to enter a
   command argument (e.g. 'show ?') and describes each possible
   argument.
2. Partial help is provided when an abbreviated argument is entered
   and you want to know what arguments match the input
   (e.g. 'show pr?'.
"#);
                println!("\nAvailable commands");
                println!("\n ");
                
                if matches!(context.current_mode, Mode::UserMode) {
                    println!("enable            - Enter privileged mode");
                    println!("exit              - Exit current mode");
                    println!("dhcp_enable       - Enable DHCP for networking");
                    println!("ping              - Send ICMP echo request");
                    println!("traceroute        - Display the packet transfer path");
                    println!("help              - Display available commands");
                    println!("reload            - Reload the system");
                    println!("clear             - Clear the terminal");
                    println!("show              - Some available show commands are present. To view enter 'show ?'");
                    println!("write             - Save the configuration");
                    println!("ifconfig          - Display interface configuration");
                    println!("ip                - Check the interface configurations");
                    println!("do                - With do the other commands available in other modes can be executed");
                    println!("poweroff          - Power off the system");
                }
                else if matches!(context.current_mode, Mode::PrivilegedMode) {
                    println!("config            - Enter configuration mode");
                    println!("exit              - Exit to user mode");
                    println!("help              - Display available commands");
                    println!("write             - Save the configuration");
                    println!("copy              - Copy configuration files");
                    println!("clock             - Manage system clock");
                    println!("dhcp_enable       - Enable DHCP for networking");
                    println!("ping              - Send ICMP echo request");
                    println!("traceroute        - Display the packet transfer path");
                    println!("show              - Some available show commands are present. To view enter 'show ?'");
                    println!("ifconfig          - Display interface configuration");
                    println!("reload            - Reload the system");
                    println!("clear             - Clear the terminal");
                    println!("debug             - Debug the availbale processes");
                    println!("undebug           - Undebug the availbale processes");
                    println!("ssh               - Connect via SSH or show ssh version");
                    println!("disable           - Exit the Privileged EXEC Mode and enter the USER EXEC Mode");
                    println!("ip                - Check the interface configurations");
                    println!("do                - With do the other commands available in other modes can be executed");
                    println!("poweroff          - Power off the system");
                }
                else if matches!(context.current_mode, Mode::ConfigMode) {
                    println!("hostname          - Set system hostname");
                    println!("exit              - Exit to privileged mode");
                    println!("help              - Display available commands");
                    println!("write             - Save the configuration");
                    println!("dhcp_enable       - Enable DHCP for networking");
                    println!("ping              - Send ICMP echo request");
                    println!("traceroute        - Display the packet transfer path");
                    println!("enable            - Enable services");
                    println!("disable           - Disable services");
                    println!("service password encryption - Encrypt passwords defined for the device");
                    println!("ifconfig          - Configure interface");
                    println!("clock             - Create configurations (clock set)");
                    println!("reload            - Reload the system");
                    println!("clear             - Clear the terminal");
                    println!("ip                - Check the interface configurations");
                    println!("do                - With do the other commands available in other modes can be executed");
                    println!("poweroff          - Power off the system");
                    println!("interface         - Enter the Interface Configuration Mode");
                }
                else if matches!(context.current_mode, Mode::InterfaceMode) {
                    println!("exit              - Exit to config mode");
                    println!("shutdown          - Shutdown interface");
                    println!("no                - Negate a command");
                    println!("help              - Display available commands");
                    println!("write             - Save the configuration");
                    println!("interface         - Select another interface");
                    println!("ip                - Set IP address or check for ip details");
                    println!("reload            - Reload the system");
                    println!("clear             - Clear the terminal");
                    println!("do                - With do the other commands available in other modes can be executed");
                    println!("poweroff          - Power off the system");
                }
                else if matches!(context.current_mode, Mode::VlanMode) {
                    println!("config            - Configure services");
                    println!("enable            - Enable services");
                    println!("disable           - Disable services");
                    println!("exit              - Exit to config mode");
                    println!("help              - Display available commands");
                    println!("reload            - Reload the system");
                    println!("clear             - Clear the terminal");
                    println!("do                - With do the other commands available in other modes can be executed");
                    println!("poweroff          - Power off the system");
                    println!("bridge_name       - Configures the name of a bridge");
                    println!("vlan              - Assigns VLAN ID");
                    println!("segment           - Configures VLAN segment ID");
                    println!("add               - Assigns interfaces to the bridge or protocols to the interfaces ");
                    println!("router            - Configures the name of a router");
                }
                else if matches!(context.current_mode, Mode::QosMode) {
                    println!("config            - Configure services");
                    println!("enable            - Enable services");
                    println!("disable           - Disable services");
                    println!("exit              - Exit to config mode");
                    println!("help              - Display available commands");
                    println!("reload            - Reload the system");
                    println!("clear             - Clear the terminal");
                    println!("do                - With do the other commands available in other modes can be executed");
                    println!("poweroff          - Power off the system");
                    println!("policy            - Sets the QoS policy ");
                    println!("interface         - Enables BEQ or CPQ to the interface");
                    println!("priority          - Asign priority to the interface");
                }
                else if matches!(context.current_mode, Mode::DynamicRMode) {
                    println!("config            - Configure services");
                    println!("enable            - Enable services");
                    println!("disable           - Disable services");
                    println!("exit              - Exit to config mode");
                    println!("help              - Display available commands");
                    println!("reload            - Reload the system");
                    println!("clear             - Clear the terminal");
                    println!("do                - With do the other commands available in other modes can be executed");
                    println!("poweroff          - Power off the system");
                    println!("redistribute      - Configuring redistribution capability of the protocol");
                    println!("valid             - Writing the previous configuration to the manager ");
                    println!("controller        - Changing the status of the ospf controller");
                }
                else if matches!(context.current_mode, Mode::PortSMode) {
                    println!("config            - Configure services");
                    println!("enable            - Enable services");
                    println!("disable           - Disable services");
                    println!("exit              - Exit to config mode");
                    println!("help              - Display available commands");
                    println!("reload            - Reload the system");
                    println!("clear             - Clear the terminal");
                    println!("do                - With do the other commands available in other modes can be executed");
                    println!("poweroff          - Power off the system");
                    println!("mode              - Sets the port security mode");
                    println!("max_devices       - Limits the maximum number of devices allowed per por");
                    println!("violation_status  - Configures the violation mode");
                }
                else if matches!(context.current_mode, Mode::MonitoringMode) {
                    println!("config            - Configure services");
                    println!("enable            - Enable services");
                    println!("disable           - Disable services");
                    println!("exit              - Exit to config mode");
                    println!("help              - Display available commands");
                    println!("reload            - Reload the system");
                    println!("clear             - Clear the terminal");
                    println!("do                - With do the other commands available in other modes can be executed");
                    println!("poweroff          - Power off the system");
                    println!("logging_level     - Sets the logging level");
                }
                else if matches!(context.current_mode, Mode::AutoDMode) {
                    println!("config            - Configure services");
                    println!("enable            - Enable services");
                    println!("disable           - Disable services");
                    println!("exit              - Exit to config mode");
                    println!("help              - Display available commands");
                    println!("reload            - Reload the system");
                    println!("clear             - Clear the terminal");
                    println!("do                - With do the other commands available in other modes can be executed");
                    println!("poweroff          - Power off the system");
                    println!("holdtime          - Sets the hold time for discovery messages");
                    println!("reinit            - Sets the reinitialization behavior");
                    println!("interface         - Configures the interface for the given mode");
                }
                
                println!("\n ");
}