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
                    println!("do                - With do show, the show commands available in other modes can be executed");
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
                    println!("do                - With do show, the show commands available in other modes can be executed");
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
                    println!("service password encryption - Encrypt passwords defined for the device");
                    println!("ifconfig          - Configure interface");
                    println!("clock             - Create configurations (clock set)");
                    println!("reload            - Reload the system");
                    println!("clear             - Clear the terminal");
                    println!("ip                - Check the interface configurations");
                    println!("do                - With do show, the show commands available in other modes can be executed");
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
                    println!("do                - With do show, the show commands available in other modes can be executed");
                    println!("poweroff          - Power off the system");
                }
                else if matches!(context.current_mode, Mode::VlanMode) {
                    println!("config            - Configure services");
                    println!("enable            - Enable services");
                    println!("exit              - Exit to config mode");
                    println!("help              - Display available commands");
                    println!("reload            - Reload the system");
                    println!("clear             - Clear the terminal");
                    println!("do                - With do show, the show commands available in other modes can be executed");
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
                    println!("exit                      - Exit to config mode");
                    println!("help                      - Display available commands");
                    println!("reload                    - Reload the system");
                    println!("clear                     - Clear the terminal");
                    println!("do                        - With do show, the show commands available in other modes can be executed");
                    println!("poweroff                  - Power off the system");
                    println!("Initiate                  - Initiates the IBIT upon request from the Remote Manager.");
                    println!("Get_log                   - Retrieves logs from Built-In Tests ");
                    println!("Get_status                - Retrieves the current status of a specified BIT test ");
                    println!("Clear_logs                - Clears logs of a specific BIT test to free up memory or reset error tracking");
                    println!("Set_threshold             - Configures a threshold for CBIT monitoring.");
                    println!("List_failures             - Lists recent system failures detected by BITD along with failure codes and timestamps.");
                    println!("Get_diagnostics           - Retrieves in-depth failure analysis for a specific issue detected by BITD");
                    println!("Run_health_check          - Runs a quick system-wide health check using BITD tests and returns a summary");
                    println!("Enable_auto_diagnostics   - Turns automatic failure diagnostics on or off for CBIT failures.");
                }
                else if matches!(context.current_mode, Mode::DynamicRMode) {
                    println!("config            - Configure services");
                    println!("enable            - Enable services");
                    println!("exit                  - Exit to config mode");
                    println!("help                  - Display available commands");
                    println!("reload                - Reload the system");
                    println!("clear                 - Clear the terminal");
                    println!("do                    - With do show, the show commands available in other modes can be executed");
                    println!("poweroff              - Power off the system");
                    println!("Set_remote_position   - Sets the system’s position to the value provided by the Remote Controller");
                    println!("Set_local_position    - Sets the system’s position to the value provided by the Local Operator. ");
                    println!("Provide_position      - Returns the current position data to the requester");
                    println!("Provide_time          - Returns the current time data to the requester ");
                    println!("Select_time_source    - Selects the time source ");
                    println!("Get_time_source       - Returns the currently active time source.");
                    println!("Sync_time_now         - Immediately synchronizes the system time with the currently selected time source.");
                    println!("Get_sync_status       - Retrieves synchronization status, including drift, last sync time, and accuracy.");
                    println!("Enable_holdover       - Enables or disables holdover mode, which maintains accurate time when GNSS is lost.");
                    println!("Get_holdover_status   - Returns the current holdover status and estimated accuracy.");
                    println!("Validate_time_source  - Runs a validation check on a specific time source ");
                    println!("Set_manual_time       - Allows the Local Operator or Remote Controller to manually set system time when needed.");
                    println!("Enable_security_checks- Enables or disables authentication and validation checks for time and position data.");
                    println!("Get_security_status   - Returns the status of integrity checks, including spoofing detection results.");
                }
                else if matches!(context.current_mode, Mode::PortSMode) {
                    println!("config            - Configure services");
                    println!("enable            - Enable services");
                    println!("exit                      - Exit to config mode");
                    println!("help                      - Display available commands");
                    println!("reload                    - Reload the system");
                    println!("clear                     - Clear the terminal");
                    println!("do                        - With do show, the show commands available in other modes can be executed");
                    println!("poweroff                  - Power off the system");
                    println!("emcon                     - Enables or disables Emission Control ");
                    println!("rf_mode                   - Sets the radio to either Receive-Only Mode (Rx_only) or Full-Duplex Mode (tx_rx).");
                    println!("get_rf_status             - Returns the current RF transmission mode (Rx_only or Tx/Rx) and EMCON status");
                    println!("set_power_level           - Adjusts the radio transmission power ");
                    println!("get_power_level           - Retrieves the current transmission power level.");
                    println!("lock_rf_config            - Prevents further changes to RF settings until manually unlocked by the remote controller.");
                    println!("unlock_rf_config          - Unlocks previously locked RF configuration settings.");
                    println!("force_tx_enable           - Overrides Rx_only mode and forces transmission ");
                    println!("reset_rf_settings         - Resets RF settings to default values");
                    println!("set_emcon_timer           - Enables EMCON mode for a specified duration, after which emissions are automatically re-enabled.");
                    println!("get_emcon_status          - Returns the status of EMCON mode");
                    println!("enable_rx_only_override   - Allows remote control to disable Rx_only mode when necessary ");
                    println!("log_rf_activity           - Retrieves a log of recent RF mode changes and power adjustments.");
                }
                else if matches!(context.current_mode, Mode::MonitoringMode) {
                    println!("config            - Configure services");
                    println!("enable            - Enable services");
                    println!("exit                  - Exit to config mode");
                    println!("help                  - Display available commands");
                    println!("reload                - Reload the system");
                    println!("clear                 - Clear the terminal");
                    println!("do                    - With do show, the show commands available in other modes can be executed");
                    println!("poweroff              - Power off the system");
                    println!("set_mode              - Configures the PnF Box to operate as a source, sink, or relay.");
                    println!("enable_relay          - Activates the relay function, allowing the system to forward incoming data.");
                    println!("disable_relay         - Disables the relay function, preventing the system from forwarding data.");
                    println!("get_mode              - Retrieves the current operating mode ");
                    println!("get_relay_status      - Checks whether the relay function is enabled or disabled.");
                    println!("log_relay_activity    - Fetches logs of recent relay operations for auditing and troubleshooting.");
                    println!("set_qos_priority      - Defines Quality of Service (QoS) levels for data forwarding in relay mode.");
                    println!("manual_override_relay - Forces relay mode activation or deactivation, overriding automatic system settings.");
                    println!("set_relay_timeout     - Specifies a time limit for how long the relay function remains active before auto-disabling.");
                    println!("get_relay_timeout     - Retrieves the current relay timeout setting.");
                    println!("reset_relay_setting   - Restores relay-related settings to default values.");
                    
                }
                else if matches!(context.current_mode, Mode::AutoDMode) {
                    println!("config            - Configure services");
                    println!("enable            - Enable services");
                    println!("exit                      - Exit to config mode");
                    println!("help                      - Display available commands");
                    println!("reload                    - Reload the system");
                    println!("clear                     - Clear the terminal");
                    println!("do                        - With do show, the show commands available in other modes can be executed");
                    println!("poweroff                  - Power off the system");
                    println!("set_syslog_server         - Configures the Syslog server address and port.");
                    println!("enable_syslog             - Activates Syslog forwarding with the specified log level.");
                    println!("disable_syslog            - Disables Syslog forwarding.");
                    println!("test_syslog               - Sends a test log entry to verify Syslog connectivity.");
                    println!("show_syslog_status        - Displays current Syslog configuration.");
                    println!("show_log                  - Retrieves the last n system log entries.");
                    println!("set_alert                 - Defines a custom alert threshold.");
                    println!("get_alerts                - Lists active alert configurations.");
                    println!("snmpget                   - Fetches real-time system health status via SNMP.");
                    println!("snmptrap                  - Manually triggers an SNMP trap.");
                    println!("activate_battleshort      - Enables battleshort mode, preventing automatic failover while keeping monitoring active.");
                    println!("deactivate_battleshort    - Disables battleshort mode, reactivating automatic protections.");
                    println!("battleshort_status        - Retrieves the current battleshort mode status.");
                    println!("remote_exclusive_access   - Grants the remote controller exclusive control.s");
                    println!("release_remote_access     - Restores local operator control.");
                    println!("show_remote_access_status - Displays whether local or remote control is currently active.");
                    println!("show_error_log            - Retrieves the last n critical error codes and warnings.");
                    println!("clear_ui_display          - Clears error messages from the UI display.");
                    println!("test_ui_alert             - Sends a test alert to the UI MCU for verification.");
                }
                
                println!("\n ");
}