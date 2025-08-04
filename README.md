# HashBox Remote Monitor

A real-time network monitoring application that tracks ping status and SSH voltage readings with historical data visualization for remote HashBox systems.

## Features

- **Real-time monitoring** of network connectivity via ping
- **SSH voltage monitoring** for remote systems
- **Historical data visualization** with interactive graphs
- **Event logging** with automatic file persistence
- **Statistics tracking** including uptime percentage and success rates
- **Improved historical data loading** - properly parses existing event logs to continue past sessions

## Historical Data Loading

The application now properly loads and continues from existing event logs:

- **Automatic detection** of existing `events_log.txt` files
- **Smart timestamp parsing** that extracts actual dates from event data
- **SSH event association** using previous ping timestamps for accurate dating
- **Session continuity** - starts monitoring from where it left off
- **Data validation** with export functionality for verification

### Event Log Format

The application handles the following log format:
```
[12:07:09] UP: 2025-08-04 12:07:07
[12:07:09] SSH: 11.75V
[12:07:20] UP: 2025-08-04 12:07:19
[12:07:20] SSH: 11.73V
```

## Usage

### Main Application
```bash
python heartbeat_monitor.py
```

### Test Historical Data Loading
```bash
python test_historical_data.py
```

## Configuration

The application automatically creates `heartbeat_config.json` on first run with default settings. You can edit this file or use the Settings window in the application to configure:

### Ping Settings
- **Target IP**: IP address to ping (default: 8.8.8.8)
- **Ping Interval**: Minutes and seconds between pings
- **Retry Count**: Number of retry attempts
- **Retry Delay**: Seconds between retries

### SSH Settings
- **Enable SSH**: Toggle SSH monitoring
- **SSH Host**: Remote server IP
- **SSH Username**: Login username
- **SSH Password**: Login password
- **SSH Command**: Command to execute (should return voltage)
- **SSH Timeout**: Connection timeout in seconds

### Application Settings
- **Close to System Tray**: Whether to hide app to tray when closed

> **Note**: `heartbeat_config.json` contains your personal settings and is ignored by git.

## Files

- `heartbeat_monitor.py` - Main monitoring application with tray support
- `run.bat` - Windows launcher (installs dependencies and starts app)
- `launcher.pyw` - Silent launcher (optional)
- `requirements.txt` - Python dependencies
- `README.md` - This documentation

### Auto-Generated Files (ignored by git)
- `heartbeat_config.json` - User configuration (created on first run)
- `events_log.txt` - Event log (created during monitoring) 