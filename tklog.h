//
// tklog.h - Tisvo Kernel Log Library - Public API
// Copyright (c) 2025, Tisvo. All rights reserved.
//

#pragma once

#include <ntddk.h>

//=============================================================================
// Opaque Types and Handles
//=============================================================================

// Opaque handle for a TKLOG logger instance.
// The user does not know the internal structure and interacts with it via this handle.
struct _TKLOG_INSTANCE;
typedef struct _TKLOG_INSTANCE* HTKLOG;

// Pointer to a logger handle. Used as an OUT parameter in CreateLogger.
typedef HTKLOG* PHTKLOG;

//=============================================================================
// Public Enums and Typedefs
//=============================================================================

// Log levels
typedef enum _TKLOG_LEVEL {
    TKLOG_LEVEL_TRACE = 0,
    TKLOG_LEVEL_DEBUG,
    TKLOG_LEVEL_INFO,
    TKLOG_LEVEL_WARN,
    TKLOG_LEVEL_ERROR,
    TKLOG_LEVEL_FATAL,
    TKLOG_LEVEL_OFF // This level is used to disable logging completely.
} TKLOG_LEVEL;

// Base type for log categories.
// Users can define their own categories using this type as bit flags.
// Ex:
// #define CATEGORY_GENERAL   0x00000001
// #define CATEGORY_NETWORK   0x00000002
// #define CATEGORY_FILESYS   0x00000004
// #define CATEGORY_ALL       0xFFFFFFFF
typedef ULONG TKLOG_CATEGORY;

//=============================================================================
// Optional Features
//=============================================================================

// Users who accept the performance overhead of using float/double in kernel mode
// can enable the '{f}' format specifier by defining this macro during compilation.
// #define TKLOG_ENABLE_FLOATING_POINT


//=============================================================================
// Configuration Structure
//=============================================================================

// Configuration structure used to create a new logger instance.
typedef struct _TKLOG_CONFIG {

    // The name of this logger instance (e.g., "NetworkFilter"). Used in the '{logger_name}' placeholder.
    // Must be a UNICODE string.
    PCWSTR LoggerName;

    // The minimum log level for this logger instance.
    TKLOG_LEVEL Level;

    // A bitmask of categories to be enabled for this logger instance.
    // A log message's category must have a common bit with this mask to be processed.
    // A mask of 0 means all categories are disabled. Use 0xFFFFFFFF for all.
    TKLOG_CATEGORY CategoryMask;

    // The pattern that defines the log output format.
    // Ex: "[{timestamp:HH:mm:ss}] [{level}] {message}"
    PCWSTR Pattern;

    // Output targets
    BOOLEAN EnableDebugger;     // Enable Kernel Debugger (DbgPrint) output.
    BOOLEAN EnableRingBuffer;   // Enable the in-memory ring buffer.

    // If EnableRingBuffer is TRUE, this is the size of the buffer in bytes.
    // If 0, a default size is used.
    SIZE_T RingBufferSize;

} TKLOG_CONFIG;

//=============================================================================
// Public API Functions
//=============================================================================

#ifdef __cplusplus
extern "C" {
#endif

    // Initializes the TKLOG library globally. Must be called once in the driver's DriverEntry.
    _Check_return_
        NTSTATUS
        TKLog_Init(
            _In_ PDRIVER_OBJECT DriverObject,
            _In_opt_ PUNICODE_STRING RegistryPath
        );

    // Creates a new logger instance with the specified configuration.
    _Check_return_
        NTSTATUS
        TKLog_CreateLogger(
            _In_ const TKLOG_CONFIG* Config,
            _Out_ PHTKLOG pLoggerHandle
        );

    // Destroys the specified logger instance and its associated resources.
    VOID
        TKLog_DestroyLogger(
            _In_ HTKLOG LoggerHandle
        );

    // Shuts down the TKLOG library globally and releases all resources.
    // Must be called once in the driver's Unload routine.
    VOID
        TKLog_Shutdown(VOID);

    // Dumps the contents of the ring buffer for a given logger instance.
    _Check_return_
        NTSTATUS
        TKLog_DumpRingBuffer(
            _In_ HTKLOG LoggerHandle,
            _Out_writes_bytes_to_opt_(OutputBufferSize, *BytesCopied) PCHAR OutputBuffer,
            _In_ SIZE_T OutputBufferSize,
            _Out_ PSIZE_T BytesCopied
        );

    // Internal log writing function. Users should not call this directly.
    // The macros below should be used instead.
    VOID
        TKLog_WriteInternal(
            _In_ HTKLOG LoggerHandle,
            _In_ TKLOG_LEVEL Level,
            _In_ TKLOG_CATEGORY Category,
            _In_ PCSTR Format,
            ...
        );

    // Extended internal log writing function that accepts source code location.
    VOID
        TKLog_WriteEx(
            _In_ HTKLOG LoggerHandle,
            _In_ TKLOG_LEVEL Level,
            _In_ TKLOG_CATEGORY Category,
            _In_opt_ PCSTR FunctionName,
            _In_opt_ PCSTR FileName,
            _In_ ULONG LineNumber,
            _In_ PCSTR Format,
            ...
        );

#ifdef __cplusplus
}
#endif

//=============================================================================
// Public Logging Macros
//=============================================================================

// The main writing macro that forms the basis for all logging macros.
#define TKLOG_WRITE(handle, level, format, ...) \
    if (handle) { TKLog_WriteInternal(handle, level, 0x1, format, __VA_ARGS__); }

// Level-based convenience macros for users.
#define TKLOG_TRACE(handle, format, ...) \
    TKLOG_WRITE(handle, TKLOG_LEVEL_TRACE, format, __VA_ARGS__)

#define TKLOG_DEBUG(handle, format, ...) \
    TKLOG_WRITE(handle, TKLOG_LEVEL_DEBUG, format, __VA_ARGS__)

#define TKLOG_INFO(handle, format, ...) \
    TKLOG_WRITE(handle, TKLOG_LEVEL_INFO, format, __VA_ARGS__)

#define TKLOG_WARN(handle, format, ...) \
    TKLOG_WRITE(handle, TKLOG_LEVEL_WARN, format, __VA_ARGS__)

#define TKLOG_ERROR(handle, format, ...) \
    TKLOG_WRITE(handle, TKLOG_LEVEL_ERROR, format, __VA_ARGS__)

#define TKLOG_FATAL(handle, format, ...) \
    TKLOG_WRITE(handle, TKLOG_LEVEL_FATAL, format, __VA_ARGS__)

// Main write macro for categorized logging.
#define TKLOG_WRITE_CAT(handle, level, category, format, ...) \
    if (handle) { TKLog_WriteInternal(handle, level, category, format, __VA_ARGS__); }

// Level-based convenience macros for users.
#define TKLOG_TRACE_CAT(handle, category, format, ...) \
    TKLOG_WRITE(handle, TKLOG_LEVEL_TRACE, category, format, __VA_ARGS__)

#define TKLOG_DEBUG_CAT(handle, category, format, ...) \
    TKLOG_WRITE(handle, TKLOG_LEVEL_DEBUG, category, format, __VA_ARGS__)

#define TKLOG_INFO_CAT(handle, category, format, ...) \
    TKLOG_WRITE(handle, TKLOG_LEVEL_INFO, category, format, __VA_ARGS__)

#define TKLOG_WARN_CAT(handle, category, format, ...) \
    TKLOG_WRITE(handle, TKLOG_LEVEL_WARN, category, format, __VA_ARGS__)

#define TKLOG_ERROR_CAT(handle, category, format, ...) \
    TKLOG_WRITE(handle, TKLOG_LEVEL_ERROR, category, format, __VA_ARGS__)

#define TKLOG_FATAL_CAT(handle, category, format, ...) \
    TKLOG_WRITE(handle, TKLOG_LEVEL_FATAL, category, format, __VA_ARGS__)

// The main writing macro for extended logging that captures source code location.
#define TKLOG_WRITE_EX(handle, level, category, format, ...) \
    if (handle) { TKLog_WriteEx(handle, level, category, __FUNCTION__, __FILE__, __LINE__, format, __VA_ARGS__); }

// Level-based convenience macros for extended logging.
#define TKLOG_TRACE_EX(handle, category, format, ...) \
    TKLOG_WRITE_EX(handle, TKLOG_LEVEL_TRACE, category, format, __VA_ARGS__)

#define TKLOG_DEBUG_EX(handle, category, format, ...) \
    TKLOG_WRITE_EX(handle, TKLOG_LEVEL_DEBUG, category, format, __VA_ARGS__)

#define TKLOG_INFO_EX(handle, category, format, ...) \
    TKLOG_WRITE_EX(handle, TKLOG_LEVEL_INFO, category, format, __VA_ARGS__)

#define TKLOG_WARN_EX(handle, category, format, ...) \
    TKLOG_WRITE_EX(handle, TKLOG_LEVEL_WARN, category, format, __VA_ARGS__)

#define TKLOG_ERROR_EX(handle, category, format, ...) \
    TKLOG_WRITE_EX(handle, TKLOG_LEVEL_ERROR, category, format, __VA_ARGS__)

#define TKLOG_FATAL_EX(handle, category, format, ...) \
    TKLOG_WRITE_EX(handle, TKLOG_LEVEL_FATAL, category, format, __VA_ARGS__)
