# Campus Messaging System - Python Edition

A client-server messaging system for campus communication with GUI and database persistence.

## Features

- **Python Implementation**: Replaced C++ with Python for easier development
- **Tkinter GUI**: User-friendly graphical interface for the client
- **SQLite Database**: Persistent storage of messages on the server
- **Real-time Messaging**: TCP-based messaging between campuses
- **Heartbeat System**: UDP heartbeat monitoring
- **Broadcast Support**: Server can broadcast messages to all campuses

## Files

- `server.py` - Server application with SQLite database
- `client.py` - Client application with Tkinter GUI
- `campus_messages.db` - SQLite database (created automatically)

## Requirements

```bash
pip install tk
```

Note: Python 3.x comes with tkinter and sqlite3 by default on most systems.

## Running the Application

### 1. Start the Server

```bash
python server.py
```

Server commands:
- `list` - List connected campuses
- `messages` - Show recent messages from database
- `broadcast` - Send broadcast message to all campuses
- `quit` - Shutdown server

### 2. Start Client(s)

```bash
python client.py
```

You can run multiple clients for different campuses.

## Campus Credentials

| Campus    | Password      |
|-----------|---------------|
| Islamabad | NU-ISB-123   |
| Lahore    | NU-LHR-123   |
| Karachi   | NU-KHI-123   |
| Peshawar  | NU-PSW-123   |
| CFD       | NU-CFD-123   |
| Multan    | NU-MLT-123   |

## Using the Client GUI

1. **Connect**: Select your campus and click "Connect"
2. **Send Message**: 
   - Choose destination campus
   - Enter department name
   - Type your message
   - Click "Send Message"
3. **View Messages**: Check the "Inbox" tab for received messages
4. **View Broadcasts**: Check the "Broadcasts" tab for server announcements

## Database Schema

### messages table
- id (PRIMARY KEY)
- timestamp (TEXT)
- from_campus (TEXT)
- from_dept (TEXT)
- to_campus (TEXT)
- message (TEXT)

### connection_log table
- id (PRIMARY KEY)
- timestamp (TEXT)
- campus (TEXT)
- ip_address (TEXT)
- event_type (TEXT)

## Network Ports

- TCP Port: 5000 (messaging)
- UDP Port: 6000 (heartbeat/broadcasts)
- Client UDP: 7000+ (dynamically assigned)

## Advantages Over C++ Version

1. **No Compilation Errors**: Pure Python, no include path issues
2. **GUI Interface**: Visual interface instead of command-line
3. **Database Persistence**: Messages saved to SQLite database
4. **Cross-platform**: Works on Windows, Linux, and macOS
5. **Easier to Maintain**: Python code is more readable and maintainable
