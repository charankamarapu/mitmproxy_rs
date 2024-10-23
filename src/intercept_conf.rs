use anyhow::{anyhow, ensure};
use winapi::um::processthreadsapi::OpenProcess;
use winapi::um::winnt::{HANDLE, PROCESS_QUERY_INFORMATION};
use winapi::shared::ntdef::NTSTATUS; // Correct import for NTSTATUS
use winapi::um::handleapi::CloseHandle;
use winapi::shared::minwindef::{DWORD, ULONG};
use winapi::ctypes::c_void;
use winapi::shared::basetsd::ULONG_PTR;

pub type PID = u32;

#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: PID,
    pub process_name: Option<String>,
}

#[derive(PartialEq, Eq, Debug, Clone)]
pub struct InterceptConf {
    default: bool,
    actions: Vec<Action>,
}

#[derive(PartialEq, Eq, Debug, Clone)]
enum Action {
    Include(Pattern),
    Exclude(Pattern),
}

// Define the PROCESS_BASIC_INFORMATION structure
#[repr(C)]
pub struct PROCESS_BASIC_INFORMATION {
    pub ExitStatus: NTSTATUS,
    pub PebBaseAddress: *mut c_void,
    pub AffinityMask: ULONG_PTR,
    pub BasePriority: ULONG,
    pub UniqueProcessId: HANDLE,
    pub InheritedFromUniqueProcessId: HANDLE,
}

// Import the function for querying process information
#[link(name = "ntdll")]
extern "system" {
    pub fn NtQueryInformationProcess(
        ProcessHandle: HANDLE,
        ProcessInformationClass: u32,
        ProcessInformation: *mut c_void,
        ProcessInformationLength: DWORD,
        ReturnLength: *mut DWORD,
    ) -> NTSTATUS;
}

#[derive(PartialEq, Eq, Debug, Clone)]
enum Pattern {
    Pid(PID),
    Process(String),
}

impl Pattern {
    #[inline(always)]
    fn matches(&self, process_info: &ProcessInfo) -> bool {
        match self {
            Pattern::Pid(pid) => process_info.pid == *pid,
            Pattern::Process(name) => process_info
                .process_name
                .as_ref()
                .map(|n| n.contains(name))
                .unwrap_or(false),
        }
    }
}

impl TryFrom<&str> for InterceptConf {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let val = value.trim();
        if val.is_empty() {
            return Ok(InterceptConf::new(vec![]));
        }
        let actions: Vec<&str> = val.split(',').collect();
        InterceptConf::try_from(actions).map_err(|_| anyhow!("invalid intercept spec: {}", value))
    }
}

impl<T: AsRef<str>> TryFrom<Vec<T>> for InterceptConf {
    type Error = anyhow::Error;

    fn try_from(value: Vec<T>) -> Result<Self, Self::Error> {
        let actions = value
            .into_iter()
            .map(|a| Action::try_from(a.as_ref()))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(InterceptConf::new(actions))
    }
}

impl TryFrom<&str> for Action {
    type Error = anyhow::Error;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let value = value.trim();
        if let Some(value) = value.strip_prefix('!') {
            Ok(Action::Exclude(Pattern::try_from(value)?))
        } else {
            Ok(Action::Include(Pattern::try_from(value)?))
        }
    }
}

impl TryFrom<&str> for Pattern {
    type Error = anyhow::Error;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let value = value.trim();
        ensure!(!value.is_empty(), "pattern must not be empty");
        Ok(match value.parse::<PID>() {
            Ok(pid) => Pattern::Pid(pid),
            Err(_) => Pattern::Process(value.to_string()),
        })
    }
}

impl std::fmt::Display for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Action::Include(pat) => write!(f, "{}", pat),
            Action::Exclude(pat) => write!(f, "!{}", pat),
        }
    }
}

impl std::fmt::Display for Pattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Pattern::Pid(pid) => write!(f, "{}", pid),
            Pattern::Process(name) => write!(f, "{}", name),
        }
    }
}

impl InterceptConf {
    fn new(actions: Vec<Action>) -> Self {
        let default = matches!(actions.first(), Some(Action::Exclude(_)));
        Self { default, actions }
    }

    pub fn disabled() -> Self {
        Self::new(vec![])
    }

    pub fn actions(&self) -> Vec<String> {
        self.actions.iter().map(|a| a.to_string()).collect()
    }

    pub fn default(&self) -> bool {
        self.default
    }

    pub fn should_intercept(&self, process_info: &ProcessInfo) -> bool {
        let mut intercept = self.default;
        for action in &self.actions {
            match action {
                Action::Include(pattern) => {
                    if pattern.matches(process_info) || self.matches_parent(pattern, process_info.pid) {
                        intercept = true; // Intercept if it matches or if a parent matches
                    }
                }
                Action::Exclude(pattern) => {
                    intercept = intercept && !pattern.matches(process_info);
                }
            }
        }
        intercept
    }

    // Function to check if any parent of the given PID matches the pattern
    fn matches_parent(&self, pattern: &Pattern, pid: PID) -> bool {
        let mut current_pid = pid;

        while let Some(parent) = self.get_parent_pid(current_pid) {
            if pattern.matches(&ProcessInfo {
                pid: parent,
                process_name: None, // Or retrieve the actual process name if needed
            }) {
                return true; // A matching parent was found
            }
            current_pid = parent; // Move up the process tree
        }
        false // No matching parent found
    }

    // Function to get the parent PID of a given PID
    pub fn get_parent_pid(&self, pid: DWORD) -> Option<DWORD> {
        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_INFORMATION, 0, pid);
            if handle.is_null() {
                return None; // Failed to open process
            }

            let mut process_basic_info: PROCESS_BASIC_INFORMATION = std::mem::zeroed();
            let mut return_length: DWORD = 0;

            // Query the process information
            let status = NtQueryInformationProcess(
                handle,
                0, // ProcessBasicInformation
                &mut process_basic_info as *mut _ as *mut winapi::ctypes::c_void, // Use winapi's c_void
                std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as DWORD,
                &mut return_length,
            );

            CloseHandle(handle);

            // Check for successful status
            if status == 0 { // This needs to check against STATUS_SUCCESS
                return Some(process_basic_info.InheritedFromUniqueProcessId as DWORD);
            }
        }
        None // Could not retrieve parent PID
    }



    pub fn description(&self) -> String {
        if self.actions.is_empty() {
            return "Intercept nothing.".to_string();
        }
        let parts: Vec<String> = self
            .actions
            .iter()
            .map(|a| match a {
                Action::Include(Pattern::Pid(pid)) => format!("Include PID {}.", pid),
                Action::Include(Pattern::Process(name)) => {
                    format!("Include processes matching \"{}\".", name)
                }
                Action::Exclude(Pattern::Pid(pid)) => format!("Exclude PID {}.", pid),
                Action::Exclude(Pattern::Process(name)) => {
                    format!("Exclude processes matching \"{}\".", name)
                }
            })
            .collect();
        parts.join(" ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_intercept_conf() {
        let a = ProcessInfo {
            pid: 1,
            process_name: Some("a".into()),
        };
        let b = ProcessInfo {
            pid: 2242,
            process_name: Some("mitmproxy".into()),
        };

        let conf = InterceptConf::try_from("1,2,3").unwrap();
        assert!(conf.should_intercept(&a));
        assert!(!conf.should_intercept(&b));

        let conf = InterceptConf::try_from("").unwrap();
        assert!(!conf.should_intercept(&a));
        assert!(!conf.should_intercept(&b));
        assert_eq!(conf, InterceptConf::disabled());

        let conf = InterceptConf::try_from("!1234").unwrap();
        assert!(conf.should_intercept(&a));
        assert!(conf.should_intercept(&b));

        let conf = InterceptConf::try_from("mitm").unwrap();
        assert!(!conf.should_intercept(&a));
        assert!(conf.should_intercept(&b));

        assert!(InterceptConf::try_from(",,").is_err());
    }
}
