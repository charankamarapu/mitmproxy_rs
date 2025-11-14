# Windows Redirector - FFI Library

This is a standalone Windows network traffic redirector library that can be called from Go programs via FFI (Foreign Function Interface). It has been made independent of the main mitmproxy workspace to simplify deployment and integration.

## Overview

The Windows Redirector captures network traffic using WinDivert, decides which connections to intercept based on configuration, and can redirect packets to local proxy services. It's designed to work without IPC communication, making it suitable for FFI integration.

## Architecture Independence

This library has been designed to be **independent of the main mitmproxy workspace** (`../../src/`) for the following reasons:

1. **FFI Integration**: Can be built as a standalone library (`cdylib`/`staticlib`) for Go integration
2. **Simplified Deployment**: No need to distribute the entire mitmproxy source tree
3. **Local Type Definitions**: Contains minimal local implementations of required types
4. **No IPC Dependencies**: Removes complex protobuf and socket communication code

## Key Changes from Workspace Version

### Dependencies Removed
- `mitmproxy` crate dependency (replaced with local types)
- `prost` (protobuf serialization - no longer needed)
- `uds_windows` (Unix socket communication - no longer needed)

### Local Type Definitions
```rust
pub struct ProcessInfo {
    pub pid: u32,
    pub process_name: Option<String>,
}

pub struct IncomingTrafficInfo {
    pub is_open_event_sent: bool,
    pub written_bytes: u32,
    pub read_bytes: u32,
}

pub struct LocalInterceptConf {
    pub intercept_pids: Vec<u32>,
    pub description: String,
}
```

### IPC Code Commented Out
All IPC-related code has been commented out but preserved for reference:
- IPC message handling
- Protobuf encoding/decoding
- Socket communication

## FFI Interface

The library exposes the following C-compatible functions for Go integration:

### Core Functions

#### `start_redirector() -> i32`
Starts the redirector in a background thread. Returns:
- `0`: Success
- `-1`: Already running
- `-2`: Initialization error

```go
// Go usage example
/*
#include <stdint.h>

int32_t start_redirector(void);
int32_t stop_redirector(void);
int32_t set_redirector_config(const char* json);
int32_t get_redirector_status(void);
*/
import "C"

func startRedirector() error {
    result := C.start_redirector()
    if result != 0 {
        return fmt.Errorf("failed to start redirector: %d", result)
    }
    return nil
}
```

#### `stop_redirector() -> i32`
Stops the redirector. Returns:
- `0`: Success
- `-1`: Not running

#### `set_redirector_config(json: *const c_char) -> i32`
Sets intercepting configuration via JSON string. Returns:
- `0`: Success
- `-1`: Invalid JSON pointer
- `-2`: JSON parsing error
- `-3`: String conversion error

**Configuration JSON format:**
```json
{
  "intercept_pids": [1234, 5678],
  "description": "Intercept processes 1234 and 5678"
}
```

#### `get_redirector_status() -> i32`
Returns current status:
- `0`: Stopped
- `1`: Running

### Configuration Management

#### `initialize_global_config()`
Initializes global configuration state (call before other functions).

#### `update_app_port(port: u16)`
Updates the application port for incoming traffic interception.

## Building

### As a Dynamic Library (for Go FFI)
```bash
cargo build --release
# Creates: target/release/windows_redirector.dll
```

### As a Static Library
```bash
cargo build --release --target x86_64-pc-windows-msvc
# Creates: target/x86_64-pc-windows-msvc/release/libwindows_redirector.a
```

### Cross-compilation (if building from non-Windows)
```bash
rustup target add x86_64-pc-windows-msvc
cargo build --target x86_64-pc-windows-msvc --release
```

## Go Integration Example

### 1. Create C Header (windows_redirector.h)
```c
#ifndef WINDOWS_REDIRECTOR_H
#define WINDOWS_REDIRECTOR_H

#include <stdint.h>

// Core redirector functions
int32_t start_redirector(void);
int32_t stop_redirector(void);
int32_t set_redirector_config(const char* json);
int32_t get_redirector_status(void);

// Configuration functions
void initialize_global_config(void);
void update_app_port(uint16_t port);

#endif // WINDOWS_REDIRECTOR_H
```

### 2. Go Integration Code
```go
package main

/*
#cgo CFLAGS: -I.
#cgo LDFLAGS: -L. -lwindows_redirector -lws2_32 -lkernel32 -ladvapi32 -luserenv -lntdll

#include "windows_redirector.h"
#include <stdlib.h>
*/
import "C"
import (
    "encoding/json"
    "fmt"
    "unsafe"
)

type RedirectorConfig struct {
    InterceptPIDs []uint32 `json:"intercept_pids"`
    Description   string   `json:"description"`
}

type WindowsRedirector struct {
    running bool
}

func NewWindowsRedirector() *WindowsRedirector {
    C.initialize_global_config()
    return &WindowsRedirector{running: false}
}

func (r *WindowsRedirector) Start() error {
    if r.running {
        return fmt.Errorf("redirector already running")
    }
    
    result := C.start_redirector()
    if result != 0 {
        return fmt.Errorf("failed to start redirector: %d", result)
    }
    
    r.running = true
    return nil
}

func (r *WindowsRedirector) Stop() error {
    if !r.running {
        return fmt.Errorf("redirector not running")
    }
    
    result := C.stop_redirector()
    if result != 0 {
        return fmt.Errorf("failed to stop redirector: %d", result)
    }
    
    r.running = false
    return nil
}

func (r *WindowsRedirector) SetConfig(config RedirectorConfig) error {
    jsonBytes, err := json.Marshal(config)
    if err != nil {
        return fmt.Errorf("failed to marshal config: %v", err)
    }
    
    cJson := C.CString(string(jsonBytes))
    defer C.free(unsafe.Pointer(cJson))
    
    result := C.set_redirector_config(cJson)
    if result != 0 {
        return fmt.Errorf("failed to set config: %d", result)
    }
    
    return nil
}

func (r *WindowsRedirector) SetAppPort(port uint16) {
    C.update_app_port(C.uint16_t(port))
}

func (r *WindowsRedirector) IsRunning() bool {
    status := C.get_redirector_status()
    return status == 1
}

// Usage example
func main() {
    redirector := NewWindowsRedirector()
    
    // Set application port
    redirector.SetAppPort(8080)
    
    // Configure which processes to intercept
    config := RedirectorConfig{
        InterceptPIDs: []uint32{1234, 5678},
        Description:   "Intercept specific processes",
    }
    
    if err := redirector.SetConfig(config); err != nil {
        panic(fmt.Sprintf("Config error: %v", err))
    }
    
    // Start redirecting
    if err := redirector.Start(); err != nil {
        panic(fmt.Sprintf("Start error: %v", err))
    }
    
    fmt.Println("Redirector started successfully")
    
    // Your application logic here...
    
    // Stop when done
    if err := redirector.Stop(); err != nil {
        fmt.Printf("Stop error: %v\n", err)
    }
}
```

### 3. Build Instructions for Go

1. Build the Rust library:
```bash
cd /path/to/mitmproxy_rs/mitmproxy-windows/redirector
cargo build --release
```

2. Copy library to your Go project:
```bash
cp target/release/windows_redirector.dll /path/to/your/go/project/
```

3. Build Go application:
```bash
go build -ldflags="-s -w" main.go
```

## Requirements

### Runtime Requirements
- Windows 10/11 (x64)
- WinDivert kernel driver installed
- Administrator privileges (required for WinDivert)

### Development Requirements
- Rust 1.70+
- Windows SDK
- Go 1.19+ (for FFI integration)

## WinDivert Installation

1. Download WinDivert from: https://www.reqrypt.org/windivert.html
2. Extract to a location accessible by your application
3. Ensure `WinDivert.dll` and `WinDivert64.sys` are in your application's directory or PATH

## Security Considerations

- Requires administrator privileges
- WinDivert driver must be properly signed on production systems
- Consider implementing proper process validation before interception
- Monitor for potential privilege escalation vectors

## Troubleshooting

### Common Issues

1. **"WinDivert driver not found"**
   - Ensure WinDivert.dll is in the same directory as your executable
   - Check that you have administrator privileges

2. **"Access denied" errors**
   - Run your application as Administrator
   - Check Windows Defender/antivirus settings

3. **Build fails with "boringtun" dependency error**
   - This may occur if cargo is trying to use workspace-level dependencies
   - Try building from a clean environment or remove any workspace Cargo.lock files

4. **Go linking errors**
   - Ensure all required Windows libraries are linked: `-lws2_32 -lkernel32 -ladvapi32 -luserenv -lntdll`
   - Check that the Rust library is built for the same architecture as your Go binary

## Performance Considerations

- The redirector processes all TCP traffic, so performance depends on network load
- Consider filtering rules to minimize unnecessary packet processing
- Monitor memory usage with long-running instances

## Differences from IPC Version

This FFI version differs from the original IPC-based version in several ways:

1. **No Inter-Process Communication**: Configuration is set via FFI calls rather than IPC messages
2. **Simplified Event Handling**: No socket events or data events are sent to external processes
3. **Local Configuration**: All configuration is managed within the library's memory space
4. **Synchronous API**: FFI calls are synchronous rather than asynchronous message passing

## License

LGPL-3.0-or-later (same as parent mitmproxy project)
