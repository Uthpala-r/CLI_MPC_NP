use chrono::{DateTime, Local, NaiveDateTime, Duration};

pub struct Clock {
    pub time: String,
    pub date: String,
    custom_datetime: Option<DateTime<Local>>,
    start_time: DateTime<Local>,
    device_model: String,
}

impl Clock {
    pub fn new() -> Self {
        Clock {
            time: String::new(),
            date: String::new(),
            custom_datetime: None,
            start_time: Local::now(),  
            device_model: "PNF".to_string(),
        }
    }

    pub fn set_time(&mut self, time: &str) -> Result<(), String> {
        if !time.contains(':') || time.split(':').count() != 3 {
            return Err("Invalid time format. Expected HH:MM:SS".to_string());
        }
        
        let parts: Vec<&str> = time.split(':').collect();
        let (hours, minutes, seconds) = (
            parts[0].parse::<u32>().map_err(|_| "Invalid hours")?,
            parts[1].parse::<u32>().map_err(|_| "Invalid minutes")?,
            parts[2].parse::<u32>().map_err(|_| "Invalid seconds")?
        );
        
        if hours >= 24 || minutes >= 60 || seconds >= 60 {
            return Err("Invalid time values".to_string());
        }

        // Always update the time string
        self.time = time.to_string();

        // Try to update custom_datetime if we have a date
        self.update_custom_datetime();
        
        Ok(())
    }

    pub fn set_date(&mut self, day: u8, month: &str, year: u16) -> Result<(), String>  {
        let max_days = match month {
            "February" => if year % 4 == 0 { 29 } else { 28 },
            "April" | "June" | "September" | "November" => 30,
            _ => 31
        };

        if day == 0 || day > max_days {
            return Err(format!("Invalid day {} for month {}", day, month));
        }

        // Always update the date string
        self.date = format!("{} {} {}", day, month, year);

        // Try to update custom_datetime if we have a time
        self.update_custom_datetime();
        
        Ok(())
    }

    pub fn update_custom_datetime(&mut self) {
        if !self.time.is_empty() && !self.date.is_empty() {
            if let Ok(naive_time) = NaiveDateTime::parse_from_str(
                &format!("{} {}", self.date, self.time),
                "%d %B %Y %H:%M:%S"
            ) {
                self.custom_datetime = Some(DateTime::from_naive_utc_and_offset(
                    naive_time,
                    Local::now().offset().clone()
                ));
            }
        }
    }

    pub fn get_current_datetime(&self) -> DateTime<Local> {
        self.custom_datetime.unwrap_or_else(Local::now)
    }

    pub fn get_uptime(&self) -> Duration {
        Local::now().signed_duration_since(self.start_time)
    }

    pub fn format_uptime(&self) -> String {
        let duration = self.get_uptime();
        let total_seconds = duration.num_seconds();
        
        let hours = total_seconds / 3600;
        let minutes = (total_seconds % 3600) / 60;
        let seconds = total_seconds % 60;

        format!("{} uptime is {} hours, {} minutes, {} seconds",
            self.device_model,
            hours,
            minutes,
            seconds
        )
    }
}


pub fn handle_clock_set(time: &str, day: u8, month: &str, year: u16, clock: &mut Clock) -> Result<(), String> {
    if !time.is_empty() {
        clock.set_time(time)?;
    }
    if day != 0 {
        clock.set_date(day, month, year)?;
    }
    
    println!("Clock updated successfully to {} {} {} {}.", time, day, month, year);
    Ok(())

}


pub fn parse_clock_set_input(input: &str) -> Result<(&str, u8, &str, u16), String> {
    let parts: Vec<&str> = input.split_whitespace().collect();

    if parts.len() < 5 {
        return Err("Incomplete command. Usage: clock set <hh:mm:ss> <day> <month> <year>".to_string());
    }

    let time = parts[1];
    let time_parts: Vec<&str> = time.split(':').collect();
    if time_parts.len() != 3 {
        return Err("Invalid time format. Expected hh:mm:ss.".to_string());
    }

    let hour: u8 = time_parts[0].parse().map_err(|_| "Invalid hour.".to_string())?;
    let minute: u8 = time_parts[1].parse().map_err(|_| "Invalid minute.".to_string())?;
    let second: u8 = time_parts[2].parse().map_err(|_| "Invalid second.".to_string())?;

    if hour > 23 {
        return Err("Hour must be between 0 and 23.".to_string());
    }
    if minute > 59 {
        return Err("Minute must be between 0 and 59.".to_string());
    }
    if second > 59 {
        return Err("Second must be between 0 and 59.".to_string());
    }

    let day: u8 = parts[2].parse().map_err(|_| "Invalid day. Expected a number between 1 and 31.".to_string())?;
    if !(1..=31).contains(&day) {
        return Err("Invalid day. Expected a number between 1 and 31.".to_string());
    }

    let month_input = parts[3].to_lowercase();
    let valid_months = [
        "January", "February", "March", "April", "May", "June",
        "July", "August", "September", "October", "November", "December",
    ];

    // Collect all months that start with the given input
    let matched_months: Vec<&&str> = valid_months.iter()
        .filter(|m| m.to_lowercase().starts_with(&month_input))
        .collect();

    let month = match matched_months.len() {
        1 => *matched_months[0],
        0 => return Err("Invalid month. Expected a valid month name or abbreviation.".to_string()),
        _ => return Err("Ambiguous month name. Please provide a more specific input.".to_string()),
    };

    let year: u16 = parts[4].parse().map_err(|_| "Invalid year. Expected a number between 1993 and 2035.".to_string())?;
    if !(1993..=2035).contains(&year) {
        return Err("Invalid year. Expected a number between 1993 and 2035.".to_string());
    }

    Ok((time, day, month, year))
}


pub fn handle_show_clock(clock: &Clock) {
    let current = clock.get_current_datetime();
    println!(
        "Current clock: {} {}",
        current.format("%d %B %Y"),
        current.format("%H:%M:%S")
    );
}

pub fn handle_show_uptime(clock: &Clock) {
    println!("{}", clock.format_uptime());
}
