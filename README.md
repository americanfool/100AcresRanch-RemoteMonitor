# Heartbeat Sensor Monitor

A real-time network monitoring application that tracks ping status and SSH voltage readings with historical data visualization.

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

Edit `heartbeat_config.json` to configure:
- Target IP address
- Ping intervals
- SSH connection settings
- Retry parameters

## Files

- `heartbeat_monitor.py` - Main monitoring application
- `test_historical_data.py` - Test app for historical data loading
- `events_log.txt` - Event log file (auto-generated)
- `heartbeat_config.json` - Configuration file
- `requirements.txt` - Python dependencies 