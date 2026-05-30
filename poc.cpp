#include <windows.h>
#include <stdio.h>
#include <winternl.h>

// IOCTL code from the driver (0x222014)
#define IOCTL_PROCESS_TERMINATE 0x222014

// Driver device name
#define DEVICE_NAME L"\\\\.\\BootRepair"

// Function prototypes
NTSYSAPI NTSTATUS NTAPI ZwTerminateProcess(HANDLE ProcessHandle, NTSTATUS ExitStatus);

int main(int argc, char* argv[]) {
    
    // Exits if no argument is passed
    if (argc != 2) {
        return 1;
    }

    // Parse PID from command line
    DWORD pid = (DWORD)strtoul(argv[1], NULL, 10);
    if (pid == 0) {
        printf("Invalid PID: %s\n", argv[1]);
        return 1;
    }

    HANDLE hDevice;
    DWORD bytesReturned;
    BOOL result;
    NTSTATUS status;

    // Open the device
    hDevice = CreateFileW(DEVICE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    // Check if driver is running
    if (hDevice == INVALID_HANDLE_VALUE) {
        printf("Failed to open device. Error: %lu\n", GetLastError());

        // Try to get more details
        if (GetLastError() == ERROR_FILE_NOT_FOUND) {
            printf("Driver may not be installed or not running.\n");
        }
        return 1;
    }

    // Send IOCTL to terminate the process
    result = DeviceIoControl(hDevice,
        IOCTL_PROCESS_TERMINATE,
        &pid, sizeof(pid),              // Input buffer with PID
        NULL, 0,                        // Output buffer (none)
        &bytesReturned,
        NULL);

    if (result) {
        printf("Successfully sent termination request for PID %lu\n", pid);
    }
    else {
        printf("DeviceIoControl failed. Error: %lu\n", GetLastError());

        // Translate common NTSTATUS errors
        if (GetLastError() == 0xC0000001) {
            printf("Error: Access denied.\n");
        }
        else if (GetLastError() == 0xC0000206) {
            printf("Error: Invalid parameters.\n");
        }
    }

    // Close the device handle
    CloseHandle(hDevice);

    return result ? 0 : 1;
}