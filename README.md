# Nazamey ZKTECO Devices

[![PHP Version](https://img.shields.io/badge/php-%3E%3D7.0-blue.svg)](https://php.net/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Packagist](https://img.shields.io/packagist/v/nazamey/zktecodevices.svg)](https://packagist.org/packages/nazamey/zktecodevices)
[![Downloads](https://img.shields.io/packagist/dt/nazamey/zktecodevices.svg)](https://packagist.org/packages/nazamey/zktecodevices)

A comprehensive PHP library for connecting to and extracting data from ZKTeco fingerprint attendance devices. This library provides a complete implementation of the ZKTeco protocol, enabling you to retrieve user data, attendance records, and device information.

## ✨ Features

- 🔌 **Full Protocol Support** - Complete ZKTeco TCP/UDP communication protocol
- 👥 **User Management** - Extract user information, privileges, and access cards
- 📊 **Attendance Records** - Retrieve detailed attendance logs with timestamps
- 🔐 **Authentication** - Support for password-protected devices
- 📁 **Multiple Export Formats** - CSV, JSON export capabilities  
- 🌐 **Cross-Platform** - Works on Windows, Linux, and macOS
- 🚀 **Production Ready** - Tested with real ZKTeco devices

## 📋 Requirements

- PHP >= 7.0
- PHP Sockets extension (`ext-sockets`)
- Network access to ZKTeco device

## 📦 Installation

### Via Composer (Recommended)

```bash
composer require nazamey/zktecodevices
```

## 🚀 Quick Start

### Basic Usage

```php
<?php
require_once 'vendor/autoload.php';

use Nazamey\Zktecodevices\ZKTecoDeviceManager;

// Initialize connection
$zk = new ZKTecoDeviceManager('192.168.1.100', 4370, 0, 'auto');

try {
    // Test connection
    $zk->testConnection();
    
    // Get device information (if your abstraction exposes it)
    $deviceInfo = $zk->getDeviceInfo();
    
    // Extract users
    $users = $zk->getUsers();
    
    // Extract attendance records
    $attendance = $zk->getAttendanceLogs();
    
} catch (Exception $e) {
    echo "Error: " . $e->getMessage() . "\n";
}
?>
```

### Complete Data Extraction

```php
<?php
use Nazamey\Zktecodevices\ZKTecoDeviceManager;

$device_ip = "192.168.1.100";
$password = 0; // Device password (0 = no password)

$zk = new ZKTecoDeviceManager($device_ip, 4370, $password, 'auto');

// Example: extract all data in your preferred format
$users      = $zk->getUsers();
$attendance = $zk->getAttendanceLogs();

// Persist them as needed (CSV/JSON/DB/etc.)
?>
```




### Set Users

```bash
//    1 s't parameter int $uid Unique ID (max 65535)
//    2 nd parameter int|string $userid ID in DB (same like $uid, max length = 9, only numbers - depends device setting)
//    3 rd parameter string $name (max length = 24)
//    4 th parameter int|string $password (max length = 8, only numbers - depends device setting)
//    5 th parameter int $role Default Util::LEVEL_USER
//    6 th parameter int $cardno Default 0 (max length = 10, only numbers

//    return bool|mixed

    $zk->setUser(); 
```


## � API Documentation

### Class Methods

#### Connection Methods
- `connect()` / `testConnection()` - Establish or verify connection to the device
- `disconnect()` - Close the connection
- `isConnected()` - Check connection status

#### Data Extraction Methods
- `getUsers()` - Retrieve all user records
- `getAttendance()` / `getAttendanceLogs()` - Retrieve attendance records
- `getDeviceInfo()` - Get device information and status

#### Device Control Methods
- `enableDevice()` - Enable the device
- `disableDevice()` - Disable the device
- `getDeviceTime()` - Get device current time
- `setDeviceTime()` - Set device time

### Data Structures

#### User Record
```php
[
    'uid' => 1,                    // User ID
    'user_id' => '1001',          // Badge number
    'name' => 'John Doe',         // User name
    'privilege' => 14,            // User privilege level
    'password' => '',             // User password
    'group_id' => 1,             // Group ID
    'card' => 0                  // Card number
]
```

#### Attendance Record
```php
[
    'uid' => 1,                           // User ID
    'user_id' => '1001',                 // Badge number  
    'timestamp' => '2025-10-22 09:15:30', // Date and time
    'status' => 1,                       // Check-in/out status
    'punch' => 1,                        // Punch type
    'date' => '2025-10-22',             // Date only
    'time' => '09:15:30'                // Time only
]
```

## 🔧 Configuration

### Device Settings

```php
// Basic configuration
$device_ip = "192.168.1.100";    // Device IP address
$port = 4370;                    // Default ZKTeco port
$timeout = 60;                   // Connection timeout (seconds)
$password = 0;                   // Device password (0 = no password)

$zk = new Nazamey\Zktecodevices\ZKTecoDeviceManager($device_ip, $port, $password, 'auto');
```

### Multiple Password Attempts

```php
$passwords = [0, 123456, 88888]; // Try multiple passwords

foreach ($passwords as $password) {
    $zk = new Nazamey\Zktecodevices\ZKTecoDeviceManager($device_ip, 4370, $password, 'auto');
    try {
        $zk->testConnection();
        echo "✅ Connected with password: $password\n";
        break;
    } catch (Exception $e) {
        echo "❌ Failed with password: $password\n";
    }
}
```

## � Export Formats

You can design your own export layer on top of this abstraction. A common pattern is:

### CSV Files
- `attendance_DEVICE_TIMESTAMP.csv` - Attendance records
- `users_DEVICE_TIMESTAMP.csv` - User information  

### JSON Files
- `attendance_DEVICE_TIMESTAMP.json` - Attendance data
- `users_DEVICE_TIMESTAMP.json` - User data

### Summary Report
- `summary_DEVICE_TIMESTAMP.txt` - Complete extraction statistics

## 🔍 Tested Devices

This library is intended to work with common ZKTeco TCP/IP devices such as:

- **ZKTeco K Series** (Various firmware versions)
- **ZKTeco F18** 
- **ZKTeco MA300**
- **Various TCP/IP models**

## �️ Troubleshooting

### Common Issues

**Connection Failed**
- Verify device IP address and network connectivity
- Check if device is powered on and network-enabled
- Ensure PHP sockets extension is enabled: `php -m | grep sockets`

**Authentication Failed**
- Try different passwords: `0`, `123456`, `88888`
- Check if device requires specific authentication method

**No Data Retrieved**
- Verify device has users/attendance records
- Some devices may need specific timing between operations
- Try different connection methods (TCP/UDP)

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

### Development Setup

1. Clone the repository
2. Install dependencies: `composer install`
3. Run tests: `composer test`
4. Check code style: `composer analyse`

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
