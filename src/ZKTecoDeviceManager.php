<?php

namespace Nazamey\Zktecodevices;

use Exception;
use Nazamey\Zktecodevices\ZktecoVendor\ZKTeco as NazameyZKTeco;

/**
 * ZKTecoDeviceManager
 *
 * Framework-agnostic wrapper around the Nazamey ZKTeco implementation, designed
 * to be reused across multiple projects.
 */
class ZKTecoDeviceManager
{
    private string $ip;
    private int $port;
    private int $password;
    private $zk;
    private bool $connected = false;

    /**
     * Driver flag (semantic only in Nazamey fork: 'nazamey').
     */
    private string $driver = 'nazamey';

    /**
     * @param string $driver Semantic flag: 'nazamey', or 'auto'
     */
    public function __construct(string $ip, int $port = 4370, int $password = 0, string $driver = 'auto')
    {
        $this->ip = $ip;
        $this->port = $port;
        $this->password = $password;

        // In a pure PHP library we don't have Laravel's env() helper,
        // so we check $_ENV/$_SERVER when driver is 'auto'.
        $envDriver = $_ENV['ZK_DRIVER'] ?? $_SERVER['ZK_DRIVER'] ?? 'nazamey';
        $preferredDriver = $driver === 'auto' ? $envDriver : $driver;

        // We always use the Nazamey ZKTeco implementation (forked vendor code),
        // which also contains a setUser() method implemented via NazameyHelper.
        $this->driver = $preferredDriver === 'nazamey-style' ? 'nazamey-style' : 'nazamey';
        $this->zk = new NazameyZKTeco($ip, $port, 60, $password, false, false, false, 'UTF-8');
    }

    /**
     * Connect to the ZKTeco device.
     *
     * @throws Exception
     */
    public function connect(): bool
    {
        try {
            $result = $this->zk->connect();
            if ($result) {
                $this->connected = true;
                return true;
            }
            throw new Exception('Failed to connect to device');
        } catch (Exception $e) {
            $this->connected = false;
            throw new Exception('Connection failed: ' . $e->getMessage());
        }
    }

    /**
     * Disconnect from the device.
     */
    public function disconnect(): void
    {
        if ($this->connected && $this->zk) {
            try {
                $this->zk->disconnect();
            } catch (Exception $e) {
                // Ignore disconnect errors
            }
            $this->connected = false;
        }
    }

    /**
     * Call a simple device action (no arguments) such as restart, shutdown, etc.
     *
     * @throws Exception
     */
    public function callSimpleAction(string $action)
    {
        $allowed = [
            'version', 'osVersion', 'platform', 'fmVersion', 'pinWidth',
            'serialNumber', 'deviceName', 'getTime', 'restart', 'shutdown',
            'sleep', 'resume', 'testVoice', 'enableDevice', 'disableDevice',
            'workCode', 'ssr', 'clearAttendance', 'clearAdmin', 'clearAllUsers',
        ];

        if (!in_array($action, $allowed, true)) {
            throw new Exception('Action not allowed');
        }

        if (!method_exists($this->zk, $action)) {
            throw new Exception("Action {$action} not supported by device client");
        }

        if (!$this->connected) {
            $this->connect();
        }

        return $this->zk->{$action}();
    }

    /**
     * Get attendance logs from the device, normalized into a consistent array structure.
     *
     * @param string|null $startDate Y-m-d filter from (inclusive)
     * @param string|null $endDate   Y-m-d filter to (inclusive)
     *
     * @return array<int, array<string,mixed>>
     * @throws Exception
     */
    public function getAttendanceLogs(?string $startDate = null, ?string $endDate = null): array
    {
        if (!$this->connected) {
            $this->connect();
        }

        try {
            $attendance = $this->zk->getAttendance();

            if (empty($attendance)) {
                return [];
            }

            $logs = [];
            foreach ($attendance as $record) {
                $userId = $record['id'] ?? $record['user_id'] ?? $record['uid'] ?? 0;

                // Different client styles may return type/state vs punch/status;
                // we normalize both shapes.
                $punchRaw = $record['type'] ?? $record['punch'] ?? 0;
                $verifyRaw = $record['state'] ?? $record['status'] ?? 0;

                $timestamp = strtotime($record['timestamp']);

                if ($startDate && $timestamp < strtotime($startDate)) {
                    continue;
                }
                if ($endDate && $timestamp > strtotime($endDate . ' 23:59:59')) {
                    continue;
                }

                $logs[] = [
                    'user_id'     => $userId,
                    'timestamp'   => $timestamp,
                    'datetime'    => $record['timestamp'],
                    'status'      => $verifyRaw,
                    'verify_mode' => $verifyRaw,
                    'punch'       => $this->getPunchType($punchRaw),
                    'raw'         => $record,
                ];
            }

            return $logs;
        } catch (Exception $e) {
            throw new Exception('Failed to get attendance logs: ' . $e->getMessage());
        }
    }

    /**
     * Create or update a user on the device.
     *
     * Implemented only for the `nazamey` driver, using nazamey/zkteco `setUser()`.
     *
     * @throws Exception
     */
    public function setUser(
        int $uid,
        $userId,
        string $name,
        $password = '',
        ?int $role = null,
        int $cardNo = 0
    ) {
        if (!$this->connected) {
            $this->connect();
        }

        // Default role to a standard "user" level (0) if not provided.
        $resolvedRole = $role ?? 0;

        return $this->zk->setUser($uid, $userId, $name, $password, $resolvedRole, $cardNo);
    }

    /**
     * Normalize raw punch type into a human-readable value.
     */
    private function getPunchType($status): string
    {
        $types = [
            0   => 'check_in',
            1   => 'check_out',
            4   => 'break_out',
            5   => 'break_in',
            255 => 'overtime_in',
            256 => 'overtime_out',
        ];

        return $types[$status] ?? 'unknown';
    }

    /**
     * Quick connectivity check helper.
     */
    public function testConnection(): array
    {
        try {
            $this->connect();
            $this->disconnect();
            return ['success' => true, 'message' => 'Device connected successfully'];
        } catch (Exception $e) {
            return ['success' => false, 'message' => $e->getMessage()];
        }
    }

    /**
     * Retrieve basic device info (if supported by the client).
     */
    public function getDeviceInfo(): array
    {
        if (!$this->connected) {
            $this->connect();
        }

        try {
            if (!method_exists($this->zk, 'getDeviceInfo')) {
                throw new Exception('getDeviceInfo not supported by current driver');
            }

            $deviceInfo = $this->zk->getDeviceInfo();

            return [
                'ip'        => $this->ip,
                'port'      => $this->port,
                'connected' => $this->connected,
                'info'      => $deviceInfo,
            ];
        } catch (Exception $e) {
            return [
                'ip'        => $this->ip,
                'port'      => $this->port,
                'connected' => $this->connected,
                'error'     => $e->getMessage(),
            ];
        }
    }

    public function __destruct()
    {
        $this->disconnect();
    }
}


