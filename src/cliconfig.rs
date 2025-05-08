/// External crates for the CLI application
use serde::{Deserialize, Serialize};
use crate::execute::Mode;


/// Represents the configuration for the CLI application.

#[derive(Serialize, Deserialize, Clone)]
pub struct CliConfig {
    pub running_config: Option<String>,
    pub startup_config: Option<String>,
    pub hostname: String,  
    pub enable_password: Option<String>,          
    pub enable_secret: Option<String>,  
    pub encrypted_password: Option<String>,          
    pub encrypted_secret: Option<String>,          
    pub password_encryption: bool,
    pub domain_name: Option<String>,
    pub last_written: Option<String>,     
  
}


impl Default for CliConfig {
    
    /// Provides the default values for `CliConfig`.
    
    fn default() -> Self {
        Self {
            running_config: None,
            startup_config: None,
            hostname: "Network".to_string(),
            enable_password: None,          
            enable_secret: None,   
            encrypted_password: None,          
            encrypted_secret: None,         
            password_encryption: false, 
            domain_name: None,
            last_written: None,
            
        }
    }
}


/// Represents the current context of the CLI application.

#[derive(Clone)]
pub struct CliContext {
    pub current_mode: Mode,
    pub prompt: String,
    pub config: CliConfig,
    pub selected_interface: Option<String>,
}


impl Default for CliContext {

    /// Provides the default values for `CliContext`.
    fn default() -> Self {
        Self {
            current_mode: Mode::UserMode,
            prompt: "Network>".into(),
            config: CliConfig::default(),
            selected_interface: None,
        }
    }
}