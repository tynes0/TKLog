# TKLOG - Tisvo Kernel Log Library

TKLOG is a modern, flexible, and high-performance logging library designed for Windows kernel-mode drivers. It aims to provide developers with full control and a rich context during the driver debugging and event tracing processes.

Unlike static and singleton logging systems, TKLOG offers an instance-based architecture, allowing for the creation of multiple independent loggers with different rules and outputs for various modules within the same driver.

## ✨ Features

- **Instance-Based Architecture:** Create independent, named, and separately configured loggers for different parts of your driver (e.g., `Network`, `FileSystem`, `Config`).
- **Rich and Customizable Patterns:** Shape your log output exactly as you want with placeholders like `{timestamp:FORMAT}`, `{level}`, `{pid}`, `{tid}`, `{file}`, `{line}`, and more.
- **Modern Message Formatting:** Use structured and readable format specifiers like `{i}`, `{s}`, `{U}`, and `{p}` instead of C-style `%d`, `%s`.
- **Multiple Output Targets:** Send your logs simultaneously to the Kernel Debugger (`DbgPrint`) and an in-memory ring buffer.
- **Advanced Filtering:** Filter logs not only by their level (e.g., `INFO`, `ERROR`) but also by custom-defined categories (e.g., `CATEGORY_NETWORK`, `CATEGORY_IO`).
- **Safe and Stable:** Written entirely in C and compliant with Windows Driver Kit (WDK) standards. It uses safe functions to prevent issues like buffer overflows and deadlocks.
- **In-Memory Ring Buffer:** Keeps a copy of logs in memory, which is invaluable for post-crash analysis (BSOD). These logs can be read later using `TKLog_DumpRingBuffer`.

## 🚀 Quick Start

This example initializes the library, creates a simple logger, writes a log message, and cleans up all resources when the driver unloads.

```c
#include <ntddk.h>
#include "tklog.h" // Include our library

// Global logger handle
HTKLOG g_hMyLogger = NULL;

// Forward declaration for the unload routine
DRIVER_UNLOAD DriverUnload;

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    NTSTATUS status;
    
    // 1. Initialize the TKLOG library
    status = TKLog_Init(DriverObject, RegistryPath);
    if (!NT_SUCCESS(status)) {
        // Fail early if init fails
        return status;
    }

    // 2. Create a configuration for a logger instance
    TKLOG_CONFIG config = { 0 };
    config.LoggerName = L"MyDriverLogger";
    config.Level = TKLOG_LEVEL_INFO;
    config.CategoryMask = 0xFFFFFFFF; // Accept all categories
    config.EnableDebugger = TRUE;
    config.Pattern = L"[{timestamp:HH:mm:ss}] [{level}] {message}";

    // 3. Create the logger
    status = TKLog_CreateLogger(&config, &g_hMyLogger);
    if (!NT_SUCCESS(status)) {
        TKLog_Shutdown();
        return status;
    }

    // 4. Write your first log!
    TKLOG_INFO_EX(g_hMyLogger, "Driver successfully initialized. Welcome, {s}!", "TKLOG");

    // Set the unload routine
    DriverObject->DriverUnload = DriverUnload;

    return STATUS_SUCCESS;
}

VOID
DriverUnload(
    _In_ PDRIVER_OBJECT DriverObject
)
{
    UNREFERENCED_PARAMETER(DriverObject);
    PAGED_CODE();

    // 5. Destroy the logger you created
    if (g_hMyLogger) {
        TKLog_DestroyLogger(g_hMyLogger);
    }

    // 6. Shut down the TKLOG library
    TKLog_Shutdown();
}
```

## 📚 API Reference

### Configuration (`TKLOG_CONFIG`)

An instance of this structure is passed to `TKLog_CreateLogger` when creating a logger.

| Field            | Type           | Description                                                                                                                           |
| ---------------- | -------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| `LoggerName`     | `PCWSTR`       | The name of the logger (Unicode). Used in the `{logger_name}` placeholder.                                                            |
| `Level`          | `TKLOG_LEVEL`  | The minimum log level this logger will accept (e.g., `TKLOG_LEVEL_INFO`).                                                             |
| `CategoryMask`   | `TKLOG_CATEGORY` | A bitmask of log categories to accept. `0xFFFFFFFF` for all, `0` for none.                                                             |
| `Pattern`        | `PCWSTR`       | The pattern string that defines the output format (Unicode).                                                                          |
| `EnableDebugger` | `BOOLEAN`      | If `TRUE`, writes logs to the Kernel Debugger (`DbgPrint`).                                                                             |
| `EnableRingBuffer`| `BOOLEAN`      | If `TRUE`, writes logs to the in-memory ring buffer.                                                                                    |
| `RingBufferSize` | `SIZE_T`       | The size of the ring buffer in bytes. If `0`, a default size (64 KB) is used.                                                          |

### Pattern Placeholders (for the `Pattern` string)

You can use the following placeholders within the `Pattern` string.

| Placeholder           | Description                                                                     | Example Output            |
| --------------------- | ------------------------------------------------------------------------------- | ------------------------- |
| `{message}`           | The user's formatted log message.                                               | `File not found: 2`       |
| `{level}`             | The log level (TRACE, DEBUG, INFO, etc.).                                       | `ERROR`                   |
| `{logger_name}`       | The name of the logger instance.                                                | `NetworkFilter`           |
| `{timestamp:FORMAT}`  | The timestamp. Supports `YYYY,MM,DD,HH,mm,ss,fff` specifiers.                   | `2025-08-14 12:57:48.123` |
| `{pid}`               | The ID of the current process.                                                  | `1234`                    |
| `{tid}`               | The ID of the current thread.                                                   | `5678`                    |
| `{cpu}`               | The number of the processor core executing the code.                            | `3`                       |
| `{irql}`              | The current IRQL.                                                               | `0`                       |
| `{category}`          | The hexadecimal value of the log category.                                      | `0x4`                     |
| `{function}`          | The name of the function where the log was made (with `_EX` macros).            | `ProcessNetworkPacket`    |
| `{file}`              | The name of the source file where the log was made (with `_EX` macros).         | `network.c`               |
| `{line}`              | The line number where the log was made (with `_EX` macros).                     | `152`                     |

### Message Format Specifiers (for the log message)

Use these modern specifiers in your log messages instead of C-style `%d`.

| Specifier | C Type                 | Description                                                                                                                                  |
| :-------- | :--------------------- | :------------------------------------------------------------------------------------------------------------------------------------------- |
| `{s}`     | `const char*`          | A standard ANSI string.                                                                                                                      |
| `{U}`     | `PUNICODE_STRING`      | A pointer to a `UNICODE_STRING` structure.                                                                                                   |
| `{i}`     | `int`, `long`          | A signed integer.                                                                                                                            |
| `{u}`     | `unsigned int`, `long` | An unsigned integer.                                                                                                                         |
| `{i16}`   | `short`                | A 16-bit signed integer.                                                                                                                     |
| `{p}`     | `void*`                | A pointer address (in hexadecimal format).                                                                                                   |
| `{c}`     | `char`                 | A single character.                                                                                                                          |
| `{f}`     | `double`               | **WARNING!** Only works if the `TKLOG_ENABLE_FLOATING_POINT` macro is defined during compilation. Causes significant performance overhead in kernel mode. |

## 💡 Advanced Usage Examples

### Multiple Loggers and Category Filtering

```c
// Define categories
#define CATEGORY_GENERAL   0x1
#define CATEGORY_NETWORK   0x2

HTKLOG hNetLogger = NULL;
HTKLOG hGeneralLogger = NULL;

void SetupLoggers()
{
    // A logger that only listens for Network logs at INFO level
    TKLOG_CONFIG netConfig = { 0 };
    netConfig.LoggerName = L"Network";
    netConfig.Level = TKLOG_LEVEL_INFO;
    netConfig.CategoryMask = CATEGORY_NETWORK;
    netConfig.EnableDebugger = TRUE;
    netConfig.Pattern = L"[{logger_name}] {message}";
    TKLog_CreateLogger(&netConfig, &hNetLogger);

    // A logger that only listens for General logs at DEBUG level
    TKLOG_CONFIG genConfig = { 0 };
    genConfig.LoggerName = L"General";
    genConfig.Level = TKLOG_LEVEL_DEBUG;
    genConfig.CategoryMask = CATEGORY_GENERAL;
    genConfig.EnableDebugger = TRUE;
    genConfig.Pattern = L"[{logger_name}] {message}";
    TKLog_CreateLogger(&genConfig, &hGeneralLogger);
    
    // Fire some logs
    TKLOG_INFO_CAT(hNetLogger, CATEGORY_NETWORK, "Network packet processed."); // Will be visible
    TKLOG_INFO_CAT(hNetLogger, CATEGORY_GENERAL, "This message is filtered."); // Will not be visible (category mismatch)

    TKLOG_INFO_CAT(hGeneralLogger, CATEGORY_GENERAL, "System status is normal."); // Will be visible
    TKLOG_DEBUG_CAT(hGeneralLogger, CATEGORY_GENERAL, "Memory usage: 80%%"); // Will be visible
    TKLOG_DEBUG_CAT(hGeneralLogger, CATEGORY_NETWORK, "This is also filtered."); // Will not be visible (category mismatch)
}
```

### Dumping the Ring Buffer Content

This function can be used within an IRP handler that is called from a user-mode application via `DeviceIoControl`.

```c
void HandleReadLogIoctl(PIRP Irp, PIO_STACK_LOCATION Stack)
{
    NTSTATUS status;
    PCHAR userBuffer = Irp->AssociatedIrp.SystemBuffer;
    ULONG userBufferLength = Stack->Parameters.DeviceIoControl.OutputBufferLength;
    SIZE_T bytesCopied = 0;

    // Assuming g_hMyLogger was created earlier
    status = TKLog_DumpRingBuffer(
        g_hMyLogger,
        userBuffer,
        userBufferLength,
        &bytesCopied
    );
    
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = bytesCopied;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
}
```

## 🏗️ Building

Add `tklog.h` and `tklog.c` to your WDK-based driver project. You can adapt the examples to the `DriverEntry` and `DriverUnload` functions of your own project to start using the library.
