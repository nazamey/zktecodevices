# Nazamey ZKTECO Devices

Abstraction layer for ZKTeco attendance devices that you can reuse across projects,
exposed under the `Nazamey\Zktecodevices` namespace.

## Installation

When you publish this as a package (e.g. to Packagist or a private repository), projects can install it via:

```bash
composer require nazamey/zktecodevices
```

## Usage

```php
use Nazamey\Zktecodevices\ZKTecoDeviceManager;

$ip       = '192.168.1.201';
$port     = 4370;
$password = 0;

// Driver flag:
//  - 'nazamey' (default)
//  - 'nazamey-style' to signal usage of NazameyHelper-style behaviour
//  - 'auto' uses env ZK_DRIVER or defaults to 'nazamey'
$device = new ZKTecoDeviceManager($ip, $port, $password, 'auto');

// Test connection
$result = $device->testConnection();

// Simple admin actions (restart/shutdown/etc.)
$device->callSimpleAction('restart');

// Attendance logs (normalized)
$logs = $device->getAttendanceLogs('2025-01-01', '2025-01-31');

// Device info (if supported by current driver)
$info = $device->getDeviceInfo();
```

### Setting users

```php
$device->setUser(
    uid: 1,
    userId: '1001',
    name: 'John Doe',
    password: '1234',
    role: null,   // defaults to 0 (normal user)
    cardNo: 0
);
```


## License

MIT


