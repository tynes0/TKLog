//
// tklog.c - Tisvo Kernel Log Library - Implementation
// Copyright (c) 2025, Tisvo. All rights reserved.
//

#include "tklog.h"
#include <ntstrsafe.h> // Required for safe string operations

// Pool tags for memory allocation, makes debugging easier.
#define TKLOG_INSTANCE_POOL_TAG 'IKTT' // "TKTI" -> TKLog Instance
#define TKLOG_LOGGERNAME_POOL_TAG 'LKTT' // "TKTL" -> TKLog LoggerName
#define TKLOG_RINGBUFFER_POOL_TAG 'BRKT' // "TKBR" -> TKLog Ring Buffer

#define TKLOG_DEFAULT_RING_BUFFER_SIZE (64 * 1024) // 64 KB
// Maximum length for a single log message.
#define TKLOG_MAX_MESSAGE_LENGTH 1024

#ifndef _countof
#define _countof(array) (sizeof(array) / sizeof(array[0]))
#endif

//=============================================================================
// Internal Data Structures
//=============================================================================

// This structure holds all state for a single ring buffer.
typedef struct _TKLOG_RING_BUFFER {

    // The actual memory for the circular buffer.
    PUCHAR Buffer;

    // The total size of the buffer in bytes.
    SIZE_T Size;

    // The offset for the next write operation.
    SIZE_T Head;

    // The number of bytes currently used in the buffer (<= Size).
    SIZE_T UsedBytes;

    // A dedicated lock to protect this buffer's state.
    KSPIN_LOCK Lock;

} TKLOG_RING_BUFFER;

// This is the concrete implementation of the HTKLOG handle.
// It holds all the state for a single logger instance.
typedef struct _TKLOG_INSTANCE {

    // A linked list entry to add this instance to the global list.
    LIST_ENTRY GlobalListEntry;

    // A lock to protect this specific instance's data if needed in the future.
    KSPIN_LOCK InstanceLock;

    // A copy of the configuration that created this instance.
    TKLOG_CONFIG Config;

    // A buffer to hold the unicode logger name, since the one in Config
    // might point to temporary memory. We own this copy.
    UNICODE_STRING LoggerName;

    // A pointer to the ring buffer context, if enabled for this instance.
    TKLOG_RING_BUFFER* RingBuffer;

} TKLOG_INSTANCE;


// This structure holds the global state for the entire TKLOG library.
typedef struct _TKLOG_GLOBALS {
    KSPIN_LOCK GlobalLock;
    LIST_ENTRY LoggerListHead;
    BOOLEAN IsInitialized;
    PDRIVER_OBJECT DriverObject;
} TKLOG_GLOBALS;

//=============================================================================
// Global State
//=============================================================================

static TKLOG_GLOBALS g_TKLog = { 0 };

//=============================================================================
// Private Helper Functions
//=============================================================================

static NTSTATUS
TKLogp_RingBufferCreate(
    _In_ SIZE_T RequestedSize,
    _Out_ TKLOG_RING_BUFFER** ppRingBuffer
)
{
    NTSTATUS status = STATUS_SUCCESS;
    TKLOG_RING_BUFFER* ringBuffer = NULL;
    SIZE_T bufferSize = RequestedSize > 0 ? RequestedSize : TKLOG_DEFAULT_RING_BUFFER_SIZE;

    *ppRingBuffer = NULL;

    ringBuffer = (TKLOG_RING_BUFFER*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(TKLOG_RING_BUFFER), TKLOG_INSTANCE_POOL_TAG);
    if (!ringBuffer)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(ringBuffer, sizeof(TKLOG_RING_BUFFER));
    ringBuffer->Size = bufferSize;
    ringBuffer->Head = 0;
    ringBuffer->UsedBytes = 0;
    KeInitializeSpinLock(&ringBuffer->Lock);

    ringBuffer->Buffer = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, ringBuffer->Size, TKLOG_RINGBUFFER_POOL_TAG);
    if (!ringBuffer->Buffer)
    {
        ExFreePoolWithTag(ringBuffer, TKLOG_INSTANCE_POOL_TAG); // Clean up the context struct
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    *ppRingBuffer = ringBuffer;
    return status;
}

static VOID
TKLogp_RingBufferDestroy(
    _In_ TKLOG_RING_BUFFER* RingBuffer
)
{
    if (!RingBuffer)
    {
        return;
    }

    // Free the main buffer first.
    if (RingBuffer->Buffer)
    {
        ExFreePoolWithTag(RingBuffer->Buffer, TKLOG_RINGBUFFER_POOL_TAG);
    }

    // Free the context structure itself.
    ExFreePoolWithTag(RingBuffer, TKLOG_INSTANCE_POOL_TAG);
}

// Writes data to the ring buffer in a thread-safe manner.
static VOID
TKLogp_RingBufferWrite(
    _In_ TKLOG_RING_BUFFER* RingBuffer,
    _In_ PCSTR Data,
    _In_ SIZE_T Length
)
{
    KIRQL oldIrql;

    // Basic validation
    if (!RingBuffer || !RingBuffer->Buffer || !Data || Length == 0)
    {
        return;
    }

    KeAcquireSpinLock(&RingBuffer->Lock, &oldIrql);

    // If the incoming data is larger than the entire buffer,
    // just write the last part of it that fits.
    if (Length > RingBuffer->Size)
    {
        Data = Data + (Length - RingBuffer->Size);
        Length = RingBuffer->Size;
    }

    // Check if the data wraps around the end of the buffer
    SIZE_T spaceToEnd = RingBuffer->Size - RingBuffer->Head;
    if (Length <= spaceToEnd)
    {
        // Case 1: The data fits in a single block.
        RtlCopyMemory(RingBuffer->Buffer + RingBuffer->Head, Data, Length);
    }
    else
    {
        // Case 2: The data wraps around. Write it in two parts.
        SIZE_T firstPartSize = spaceToEnd;
        SIZE_T secondPartSize = Length - firstPartSize;

        // Copy the first part to the end of the buffer.
        RtlCopyMemory(RingBuffer->Buffer + RingBuffer->Head, Data, firstPartSize);

        // Copy the second part to the beginning of the buffer.
        RtlCopyMemory(RingBuffer->Buffer, Data + firstPartSize, secondPartSize);
    }

    // Update the head and used bytes count
    RingBuffer->Head = (RingBuffer->Head + Length) % RingBuffer->Size;

    if (RingBuffer->UsedBytes + Length <= RingBuffer->Size)
    {
        RingBuffer->UsedBytes += Length;
    }
    else
    {
        RingBuffer->UsedBytes = RingBuffer->Size; // The buffer is now full.
    }

    KeReleaseSpinLock(&RingBuffer->Lock, oldIrql);
}

// Frees all resources associated with a single logger instance.
static VOID
TKLogp_FreeInstanceResources(
    _In_ HTKLOG Instance
)
{
    if (!Instance)
    {
        return;
    }

    // Destroy the ring buffer context if it was created.
    if (Instance->RingBuffer)
    {
        TKLogp_RingBufferDestroy(Instance->RingBuffer);
        Instance->RingBuffer = NULL;
    }

    // Free the memory we allocated for the logger name.
    if (Instance->LoggerName.Buffer)
    {
        ExFreePoolWithTag(Instance->LoggerName.Buffer, TKLOG_LOGGERNAME_POOL_TAG);
    }

    // Finally, free the instance structure itself.
    ExFreePoolWithTag(Instance, TKLOG_INSTANCE_POOL_TAG);
}

// This is our custom formatter that parses {s}, {i}, {u}, {p}, etc.
// It takes the format string and a va_list and writes the result to OutputBuffer.
static NTSTATUS
TKLogp_FormatUserMessage(
    _Out_writes_bytes_(OutputBufferSize) PCHAR OutputBuffer,
    _In_ SIZE_T OutputBufferSize,
    _Out_ PSIZE_T pBytesWritten,
    _In_ _Printf_format_string_ PCSTR Format,
    _In_ va_list Args
)
{
    NTSTATUS status = STATUS_SUCCESS;
    PCHAR pCurrent = OutputBuffer;
    const PCHAR pEnd = OutputBuffer + OutputBufferSize;
    PCSTR pFormat = Format;

    while (*pFormat && pCurrent < pEnd)
    {
        if (*pFormat == '{' && *(pFormat + 1) != '{')
        {
            pFormat++; // Skip '{'
            // Use strncmp for multi-character specifiers
            if (strncmp(pFormat, "s}", 2) == 0) { // string
                PCSTR strArg = va_arg(Args, PCSTR);
                if (!strArg) strArg = "(null)";
                status = RtlStringCchCopyA(pCurrent, pEnd - pCurrent, strArg);
                if (NT_SUCCESS(status)) pCurrent += strlen(strArg);
                pFormat += 2;
            }
            else if (strncmp(pFormat, "U}", 2) == 0) { // PUNICODE_STRING
                PUNICODE_STRING ustrArg = va_arg(Args, PUNICODE_STRING);
                ANSI_STRING astr = { 0 };
                status = RtlUnicodeStringToAnsiString(&astr, ustrArg, TRUE);
                if (NT_SUCCESS(status) && astr.Buffer != NULL /*C6387*/) {
                    status = RtlStringCchCopyA(pCurrent, pEnd - pCurrent, astr.Buffer);
                    if (NT_SUCCESS(status)) pCurrent += astr.Length;
                    RtlFreeAnsiString(&astr);
                }
                pFormat += 2;
            }
            else if (strncmp(pFormat, "i}", 2) == 0) { // integer
                int intArg = va_arg(Args, int);
                status = RtlStringCchPrintfA(pCurrent, pEnd - pCurrent, "%d", intArg);
                if (NT_SUCCESS(status)) pCurrent += strlen(pCurrent);
                pFormat += 2;
            }
            else if (strncmp(pFormat, "i16}", 4) == 0) { // 16-bit integer
                SHORT i16Arg = (SHORT)va_arg(Args, int); // Promoted to int
                status = RtlStringCchPrintfA(pCurrent, pEnd - pCurrent, "%hd", i16Arg);
                if (NT_SUCCESS(status)) pCurrent += strlen(pCurrent);
                pFormat += 4;
            }
            else if (strncmp(pFormat, "u}", 2) == 0) { // unsigned integer
                unsigned int uintArg = va_arg(Args, unsigned int);
                status = RtlStringCchPrintfA(pCurrent, pEnd - pCurrent, "%u", uintArg);
                if (NT_SUCCESS(status)) pCurrent += strlen(pCurrent);
                pFormat += 2;
            }
            else if (strncmp(pFormat, "p}", 2) == 0) { // pointer
                PVOID ptrArg = va_arg(Args, PVOID);
                status = RtlStringCchPrintfA(pCurrent, pEnd - pCurrent, "0x%p", ptrArg);
                if (NT_SUCCESS(status)) pCurrent += strlen(pCurrent);
                pFormat += 2;
            }
            else if (strncmp(pFormat, "c}", 2) == 0) { // char
                char charArg = (char)va_arg(Args, int); // Promoted to int
                status = RtlStringCchPrintfA(pCurrent, pEnd - pCurrent, "%c", charArg);
                if (NT_SUCCESS(status)) pCurrent += strlen(pCurrent);
                pFormat += 2;
            }
#ifdef TKLOG_ENABLE_FLOATING_POINT
            else if (strncmp(pFormat, "f}", 2) == 0) { // float/double
                KFLOATING_SAVE floatSave = { 0 };
                status = KeSaveFloatingPointState(&floatSave);
                if (NT_SUCCESS(status)) {
                    double doubleArg = va_arg(Args, double);
                    status = RtlStringCchPrintfA(pCurrent, pEnd - pCurrent, "%f", doubleArg);
                    if (NT_SUCCESS(status)) pCurrent += strlen(pCurrent);
                    KeRestoreFloatingPointState(&floatSave);
                }
                pFormat += 2;
            }
#endif
            else { // Not a valid specifier
                *pCurrent++ = *--pFormat; // Go back to '{'
            }
        }
        else
        {
            if (*pFormat == '{' && *(pFormat + 1) == '{') pFormat++;
            *pCurrent++ = *pFormat++;
        }

        if (!NT_SUCCESS(status)) break;
    }

    *pCurrent = '\0';
    *pBytesWritten = (pCurrent - OutputBuffer);
    return status;
}

// Parses the user-defined pattern string (e.g., "[{timestamp}] {message}")
// and builds the final log string. This is the main formatting engine.
static VOID
TKLogp_FormatFinalMessage(
    _In_ HTKLOG Instance,
    _In_ TKLOG_LEVEL Level,
    _In_ TKLOG_CATEGORY Category,
    _In_opt_ PCSTR FunctionName,
    _In_opt_ PCSTR FileName,
    _In_ ULONG LineNumber,
    _In_ PCSTR UserMessage,
    _Out_writes_bytes_(FinalBufferSize) PCHAR FinalBuffer,
    _In_ SIZE_T FinalBufferSize
)
{
    NTSTATUS status;
    PCWSTR pPattern = Instance->Config.Pattern;
    if (!pPattern || !*pPattern)
    {
        // Use a sensible default pattern if none is provided.
        pPattern = L"[{timestamp:HH:mm:ss.fff}] [{level}] {message}";
    }

    PCHAR pCurrent = FinalBuffer;
    size_t remainingSize = FinalBufferSize;

    // Main loop to parse the pattern string
    while (*pPattern && remainingSize > 1)
    {
        // Check for a placeholder start '{' that is not an escaped '{{'
        if (*pPattern == L'{' && *(pPattern + 1) != L'{')
        {
            PCWSTR placeholderStart = ++pPattern; // Skip '{'
            PCWSTR placeholderEnd = wcschr(placeholderStart, L'}');

            if (!placeholderEnd) // No closing brace found, treat as literal and stop.
            {
                RtlStringCchPrintfExA(pCurrent, remainingSize, &pCurrent, &remainingSize, 0, "{%S", placeholderStart);
                break;
            }

            // --- FIX: Copy placeholder to a writable stack buffer ---
            size_t placeholderLen = placeholderEnd - placeholderStart;
            WCHAR placeholderName[64];

            if (placeholderLen < _countof(placeholderName))
            {
                // Copy the placeholder name (e.g., "timestamp:HH:mm") to the temporary buffer
                wcsncpy_s(placeholderName, _countof(placeholderName), placeholderStart, placeholderLen);
                placeholderName[placeholderLen] = L'\0'; // Ensure null-termination
            }
            else
            {
                // Placeholder is too long, treat as literal text to be safe and avoid buffer overflow.
                RtlStringCchPrintfExA(pCurrent, remainingSize, &pCurrent, &remainingSize, 0, "{%S}", placeholderStart);
                pPattern = placeholderEnd + 1;
                continue;
            }
            // --- END OF FIX ---

            // Now, perform all comparisons and operations on the writable 'placeholderName' buffer.
            if (_wcsnicmp(placeholderName, L"timestamp", 9) == 0)
            {
                LARGE_INTEGER systemTime, localTime;
                TIME_FIELDS timeFields;
                KeQuerySystemTime(&systemTime);
                ExSystemTimeToLocalTime(&systemTime, &localTime);
                RtlTimeToTimeFields(&localTime, &timeFields);

                PCWSTR fmt = L"YYYY-MM-DD HH:mm:ss.fff"; // Default format
                if (placeholderName[9] == L':')
                {
                    fmt = placeholderName + 10;
                }

                // Mini-parser for date/time format
                while (*fmt && remainingSize > 1) {
                    if (wcsncmp(fmt, L"YYYY", 4) == 0) { status = RtlStringCchPrintfExA(pCurrent, remainingSize, &pCurrent, &remainingSize, 0, "%04hd", timeFields.Year); fmt += 4; }
                    else if (wcsncmp(fmt, L"MM", 2) == 0) { status = RtlStringCchPrintfExA(pCurrent, remainingSize, &pCurrent, &remainingSize, 0, "%02hd", timeFields.Month); fmt += 2; }
                    else if (wcsncmp(fmt, L"DD", 2) == 0) { status = RtlStringCchPrintfExA(pCurrent, remainingSize, &pCurrent, &remainingSize, 0, "%02hd", timeFields.Day); fmt += 2; }
                    else if (wcsncmp(fmt, L"HH", 2) == 0) { status = RtlStringCchPrintfExA(pCurrent, remainingSize, &pCurrent, &remainingSize, 0, "%02hd", timeFields.Hour); fmt += 2; }
                    else if (wcsncmp(fmt, L"mm", 2) == 0) { status = RtlStringCchPrintfExA(pCurrent, remainingSize, &pCurrent, &remainingSize, 0, "%02hd", timeFields.Minute); fmt += 2; }
                    else if (wcsncmp(fmt, L"ss", 2) == 0) { status = RtlStringCchPrintfExA(pCurrent, remainingSize, &pCurrent, &remainingSize, 0, "%02hd", timeFields.Second); fmt += 2; }
                    else if (wcsncmp(fmt, L"fff", 3) == 0) { status = RtlStringCchPrintfExA(pCurrent, remainingSize, &pCurrent, &remainingSize, 0, "%03hd", timeFields.Milliseconds); fmt += 3; }
                    else { *pCurrent++ = (CHAR)*fmt++; remainingSize--; status = STATUS_SUCCESS; }
                    if (!NT_SUCCESS(status)) break;
                }
            }
            else if (_wcsicmp(placeholderName, L"message") == 0) {
                status = RtlStringCchCopyExA(pCurrent, remainingSize, UserMessage, &pCurrent, &remainingSize, 0);
            }
            else if (_wcsicmp(placeholderName, L"level") == 0) {
                PCSTR levelString = "?????";
                switch (Level) {
                case TKLOG_LEVEL_TRACE: levelString = "TRACE"; break;
                case TKLOG_LEVEL_DEBUG: levelString = "DEBUG"; break;
                case TKLOG_LEVEL_INFO:  levelString = "INFO "; break;
                case TKLOG_LEVEL_WARN:  levelString = "WARN "; break;
                case TKLOG_LEVEL_ERROR: levelString = "ERROR"; break;
                case TKLOG_LEVEL_FATAL: levelString = "FATAL"; break;
                default: break;
                }
                status = RtlStringCchCopyExA(pCurrent, remainingSize, levelString, &pCurrent, &remainingSize, 0);
            }
            else if (_wcsicmp(placeholderName, L"logger_name") == 0) {
                ANSI_STRING nameAnsi = { 0 };
                // Convert the string.
                status = RtlUnicodeStringToAnsiString(&nameAnsi, &Instance->LoggerName, TRUE);
                if (NT_SUCCESS(status)) {
                    // FIX: Use RtlCopyMemory with the exact length from the ANSI_STRING structure,
                    // because nameAnsi.Buffer is NOT guaranteed to be null-terminated.
                    if (remainingSize > nameAnsi.Length) {
                        RtlCopyMemory(pCurrent, nameAnsi.Buffer, nameAnsi.Length);
                        pCurrent += nameAnsi.Length;
                        remainingSize -= nameAnsi.Length;
                    }
                    // Always free the string allocated by RtlUnicodeStringToAnsiString.
                    RtlFreeAnsiString(&nameAnsi);
                }
            }
            else if (_wcsicmp(placeholderName, L"pid") == 0) {
                status = RtlStringCchPrintfExA(pCurrent, remainingSize, &pCurrent, &remainingSize, 0, "%llu", (UINT64)PsGetCurrentProcessId());
            }
            else if (_wcsicmp(placeholderName, L"tid") == 0) {
                status = RtlStringCchPrintfExA(pCurrent, remainingSize, &pCurrent, &remainingSize, 0, "%llu", (UINT64)PsGetCurrentThreadId());
            }
            else if (_wcsicmp(placeholderName, L"cpu") == 0) {
                status = RtlStringCchPrintfExA(pCurrent, remainingSize, &pCurrent, &remainingSize, 0, "%u", KeGetCurrentProcessorNumberEx(NULL));
            }
            else if (_wcsicmp(placeholderName, L"irql") == 0) {
                status = RtlStringCchPrintfExA(pCurrent, remainingSize, &pCurrent, &remainingSize, 0, "%u", KeGetCurrentIrql());
            }
            else if (_wcsicmp(placeholderName, L"function") == 0) {
                status = RtlStringCchCopyExA(pCurrent, remainingSize, FunctionName ? FunctionName : "-", &pCurrent, &remainingSize, 0);
            }
            else if (_wcsicmp(placeholderName, L"file") == 0) {
                PCSTR fileNameOnly = FileName ? strrchr(FileName, '\\') : NULL;
                if (fileNameOnly) fileNameOnly++; else fileNameOnly = FileName ? FileName : "-";
                status = RtlStringCchCopyExA(pCurrent, remainingSize, fileNameOnly, &pCurrent, &remainingSize, 0);
            }
            else if (_wcsicmp(placeholderName, L"line") == 0) {
                if (LineNumber > 0) status = RtlStringCchPrintfExA(pCurrent, remainingSize, &pCurrent, &remainingSize, 0, "%u", LineNumber);
                else status = RtlStringCchCopyExA(pCurrent, remainingSize, "-", &pCurrent, &remainingSize, 0);
            }
            else if (_wcsicmp(placeholderName, L"category") == 0) {
                status = RtlStringCchPrintfExA(pCurrent, remainingSize, &pCurrent, &remainingSize, 0, "0x%X", Category);
            }

            pPattern = placeholderEnd + 1;
        }
        else // It's a literal character
        {
            if (*pPattern == L'{' && *(pPattern + 1) == L'{') pPattern++; // Handle escaped {{

            if (remainingSize > 1) {
                *pCurrent++ = (CHAR)*pPattern;
                remainingSize--;
            }
            pPattern++;
        }
    }

    // Null-terminate the final buffer.
    *pCurrent = '\0';
}

//=============================================================================
// Public API Functions
//=============================================================================

_Use_decl_annotations_
NTSTATUS
TKLog_Init(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_opt_ PUNICODE_STRING RegistryPath
)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    PAGED_CODE();

    if (g_TKLog.IsInitialized)
    {
        return STATUS_SUCCESS;
    }

    RtlZeroMemory(&g_TKLog, sizeof(g_TKLog));
    g_TKLog.DriverObject = DriverObject;
    KeInitializeSpinLock(&g_TKLog.GlobalLock);
    InitializeListHead(&g_TKLog.LoggerListHead);
    g_TKLog.IsInitialized = TRUE;

    return STATUS_SUCCESS;
}


VOID
TKLog_Shutdown(VOID)
{
    KIRQL oldIrql;
    PAGED_CODE();

    if (!g_TKLog.IsInitialized)
    {
        return;
    }

    KeAcquireSpinLock(&g_TKLog.GlobalLock, &oldIrql);

    while (!IsListEmpty(&g_TKLog.LoggerListHead))
    {
        PLIST_ENTRY pEntry = RemoveHeadList(&g_TKLog.LoggerListHead);
        HTKLOG instance = CONTAINING_RECORD(pEntry, TKLOG_INSTANCE, GlobalListEntry);

        KeReleaseSpinLock(&g_TKLog.GlobalLock, oldIrql);
        TKLogp_FreeInstanceResources(instance);
        KeAcquireSpinLock(&g_TKLog.GlobalLock, &oldIrql);
    }

    KeReleaseSpinLock(&g_TKLog.GlobalLock, oldIrql);

    g_TKLog.IsInitialized = FALSE;
    g_TKLog.DriverObject = NULL;
}

// Dumps the contents of the ring buffer for a given logger instance.
_Use_decl_annotations_
NTSTATUS
TKLog_DumpRingBuffer(
    HTKLOG LoggerHandle,
    PCHAR OutputBuffer,
    SIZE_T OutputBufferSize,
    PSIZE_T BytesCopied
)
{
    KIRQL oldIrql;

    // 1. Validate parameters
    if (!LoggerHandle || !OutputBuffer || !BytesCopied || OutputBufferSize == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    *BytesCopied = 0;

    // Check if the ring buffer is enabled and exists for this instance
    if (!LoggerHandle->Config.EnableRingBuffer || !LoggerHandle->RingBuffer)
    {
        return STATUS_NOT_SUPPORTED;
    }

    TKLOG_RING_BUFFER* ringBuffer = LoggerHandle->RingBuffer;

    // 2. Acquire lock to get a consistent snapshot of the buffer state
    KeAcquireSpinLock(&ringBuffer->Lock, &oldIrql);

    // 3. Determine how much data to copy
    SIZE_T bytesToCopy = ringBuffer->UsedBytes;
    if (bytesToCopy > OutputBufferSize)
    {
        bytesToCopy = OutputBufferSize;
    }

    if (bytesToCopy == 0)
    {
        KeReleaseSpinLock(&ringBuffer->Lock, oldIrql);
        return STATUS_SUCCESS; // Nothing to copy
    }

    // 4. Calculate the logical 'tail' of the buffer (where the oldest data starts)
    SIZE_T tail = (ringBuffer->Head + ringBuffer->Size - ringBuffer->UsedBytes) % ringBuffer->Size;

    // 5. Perform the copy, handling wrap-around if necessary
    SIZE_T spaceToEnd = ringBuffer->Size - tail;
    if (bytesToCopy <= spaceToEnd)
    {
        // Case 1: The data to be read is in a single contiguous block.
        RtlCopyMemory(OutputBuffer, ringBuffer->Buffer + tail, bytesToCopy);
    }
    else
    {
        // Case 2: The data wraps around. Read it in two parts.
        SIZE_T firstPartSize = spaceToEnd;
        SIZE_T secondPartSize = bytesToCopy - firstPartSize;

        // Copy the first part from the tail to the end of the buffer.
        RtlCopyMemory(OutputBuffer, ringBuffer->Buffer + tail, firstPartSize);

        // Copy the second part from the beginning of the buffer.
        RtlCopyMemory(OutputBuffer + firstPartSize, ringBuffer->Buffer, secondPartSize);
    }

    // 6. Release the lock
    KeReleaseSpinLock(&ringBuffer->Lock, oldIrql);

    *BytesCopied = bytesToCopy;

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
TKLog_CreateLogger(
    const TKLOG_CONFIG* Config,
    PHTKLOG pLoggerHandle
)
{
    PAGED_CODE();
    NTSTATUS status = STATUS_SUCCESS;
    HTKLOG instance = NULL;
    KIRQL oldIrql;

    // --- Parameter Validation ---
    if (!g_TKLog.IsInitialized) 
        return STATUS_DEVICE_NOT_READY;
    if (!Config || !pLoggerHandle || !Config->LoggerName) 
        return STATUS_INVALID_PARAMETER;

    *pLoggerHandle = NULL;

    // --- Allocate memory for the instance structure ---
    instance = (HTKLOG)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(TKLOG_INSTANCE), TKLOG_INSTANCE_POOL_TAG);
    if (!instance) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(instance, sizeof(TKLOG_INSTANCE));

    // --- Copy configuration and create a persistent copy of the logger name ---
    instance->Config = *Config;

    // --- FIX: Correct length calculation for the UNICODE_STRING ---
    size_t nameLengthInChars = 0;
    status = RtlStringCchLengthW(Config->LoggerName, NTSTRSAFE_MAX_CCH, &nameLengthInChars);
    if (!NT_SUCCESS(status))
    {
        ExFreePoolWithTag(instance, TKLOG_INSTANCE_POOL_TAG);
        return status;
    }

    // Length in bytes is number of characters * size of a wide char.
    SIZE_T nameLengthInBytes = nameLengthInChars * sizeof(WCHAR);
    // Buffer needs space for the string + a null terminator.
    SIZE_T nameBufferSize = nameLengthInBytes + sizeof(WCHAR);

    instance->LoggerName.Buffer = (PWCH)ExAllocatePool2(POOL_FLAG_NON_PAGED, nameBufferSize, TKLOG_LOGGERNAME_POOL_TAG);
    if (!instance->LoggerName.Buffer)
    {
        ExFreePoolWithTag(instance, TKLOG_INSTANCE_POOL_TAG);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Set the UNICODE_STRING fields correctly in BYTES.
    instance->LoggerName.Length = (USHORT)nameLengthInBytes;
    instance->LoggerName.MaximumLength = (USHORT)nameBufferSize;

    // Now copy the string content.
    RtlCopyMemory(instance->LoggerName.Buffer, Config->LoggerName, nameLengthInBytes);
    // Ensure it's null-terminated.
    instance->LoggerName.Buffer[nameLengthInChars] = L'\0';
    // --- END OF FIX ---

    // --- Initialize instance resources ---
    KeInitializeSpinLock(&instance->InstanceLock);

    if (instance->Config.EnableRingBuffer)
    {
        status = TKLogp_RingBufferCreate(instance->Config.RingBufferSize, &instance->RingBuffer);
        if (!NT_SUCCESS(status))
        {
            ExFreePoolWithTag(instance->LoggerName.Buffer, TKLOG_LOGGERNAME_POOL_TAG);
            ExFreePoolWithTag(instance, TKLOG_INSTANCE_POOL_TAG);
            return status;
        }
    }

    // --- Add the new instance to the global list under lock ---
    KeAcquireSpinLock(&g_TKLog.GlobalLock, &oldIrql);
    InsertTailList(&g_TKLog.LoggerListHead, &instance->GlobalListEntry);
    KeReleaseSpinLock(&g_TKLog.GlobalLock, oldIrql);

    // Return the handle to the caller
    *pLoggerHandle = instance;

    return STATUS_SUCCESS;
}

VOID
TKLog_DestroyLogger(
    _In_ HTKLOG LoggerHandle
)
{
    KIRQL oldIrql;
    PAGED_CODE();

    if (!LoggerHandle)
    {
        return;
    }

    KeAcquireSpinLock(&g_TKLog.GlobalLock, &oldIrql);
    RemoveEntryList(&LoggerHandle->GlobalListEntry);
    KeReleaseSpinLock(&g_TKLog.GlobalLock, oldIrql);

    TKLogp_FreeInstanceResources(LoggerHandle);
}

VOID
TKLog_WriteInternal(
    _In_ HTKLOG LoggerHandle,
    _In_ TKLOG_LEVEL Level,
    _In_ TKLOG_CATEGORY Category,
    _In_ _Printf_format_string_ PCSTR Format,
    ...
)
{
    // 1. Check if handle is valid and level is sufficient.
    if (!LoggerHandle || Level < LoggerHandle->Config.Level)
    {
        return;
    }

    // 2. Check if the message category is enabled by the logger's mask.
    // The bitwise AND must be non-zero for a match.
    if ((Category & LoggerHandle->Config.CategoryMask) == 0)
    {
        return;
    }

    // The logic inside WriteEx needs to be duplicated here,
    // but passing NULLs to the final formatter.
    NTSTATUS status;
    CHAR userMessageBuffer[512];
    SIZE_T userMessageLength = 0;
    CHAR finalMessage[TKLOG_MAX_MESSAGE_LENGTH];

    va_list args;
    va_start(args, Format);
    status = TKLogp_FormatUserMessage(userMessageBuffer, sizeof(userMessageBuffer), &userMessageLength, Format, args);
    va_end(args);

    if (!NT_SUCCESS(status)) RtlStringCchCopyA(userMessageBuffer, sizeof(userMessageBuffer), "<MSG FORMAT ERROR>");

    TKLogp_FormatFinalMessage(LoggerHandle, Level, Category, NULL, NULL, 0, userMessageBuffer, finalMessage, sizeof(finalMessage));

    SIZE_T finalMessageLength = strlen(finalMessage);

    // Output to Kernel Debugger
    if (LoggerHandle->Config.EnableDebugger)
    {
        // Add a newline for DbgPrint if it doesn't exist.
        if (finalMessageLength > 0 && finalMessage[finalMessageLength - 1] != '\n')
        {
            DbgPrint("%s\n", finalMessage);
        }
        else
        {
            DbgPrint("%s", finalMessage);
        }
    }

    // Output to Ring Buffer
    if (LoggerHandle->Config.EnableRingBuffer && LoggerHandle->RingBuffer)
    {
        // Add a newline for the ring buffer if it doesn't exist.
        if (finalMessageLength > 0 && finalMessage[finalMessageLength - 1] != '\n')
        {
            RtlStringCchCatA(finalMessage, sizeof(finalMessage), "\n");
            finalMessageLength++;
        }
        TKLogp_RingBufferWrite(LoggerHandle->RingBuffer, finalMessage, finalMessageLength);
    }
}

VOID
TKLog_WriteEx(
    _In_ HTKLOG LoggerHandle,
    _In_ TKLOG_LEVEL Level,
    _In_ TKLOG_CATEGORY Category,
    _In_opt_ PCSTR FunctionName,
    _In_opt_ PCSTR FileName,
    _In_ ULONG LineNumber,
    _In_ _Printf_format_string_ PCSTR Format,
    ...
)
{
    // 1. Check if handle is valid and level is sufficient.
    if (!LoggerHandle || Level < LoggerHandle->Config.Level)
    {
        return;
    }

    // 2. Check if the message category is enabled by the logger's mask.
    // The bitwise AND must be non-zero for a match.
    if ((Category & LoggerHandle->Config.CategoryMask) == 0)
    {
        return;
    }

    NTSTATUS status;
    va_list args;
    CHAR userMessageBuffer[512];
    SIZE_T userMessageLength = 0;
    CHAR finalMessage[TKLOG_MAX_MESSAGE_LENGTH];

    va_start(args, Format);
    status = TKLogp_FormatUserMessage(userMessageBuffer, sizeof(userMessageBuffer), &userMessageLength, Format, args);
    va_end(args);

    if (!NT_SUCCESS(status)) RtlStringCchCopyA(userMessageBuffer, sizeof(userMessageBuffer), "<MSG FORMAT ERROR>");

    TKLogp_FormatFinalMessage(LoggerHandle, Level, Category, FunctionName, FileName, LineNumber, userMessageBuffer, finalMessage, sizeof(finalMessage));

    SIZE_T finalMessageLength = strlen(finalMessage);

    // Output to Kernel Debugger
    if (LoggerHandle->Config.EnableDebugger)
    {
        // Add a newline for DbgPrint if it doesn't exist.
        if (finalMessageLength > 0 && finalMessage[finalMessageLength - 1] != '\n')
        {
            DbgPrint("%s\n", finalMessage);
        }
        else
        {
            DbgPrint("%s", finalMessage);
        }
    }

    // Output to Ring Buffer
    if (LoggerHandle->Config.EnableRingBuffer && LoggerHandle->RingBuffer)
    {
        // Add a newline for the ring buffer if it doesn't exist.
        if (finalMessageLength > 0 && finalMessage[finalMessageLength - 1] != '\n')
        {
            RtlStringCchCatA(finalMessage, sizeof(finalMessage), "\n");
            finalMessageLength++;
        }
        TKLogp_RingBufferWrite(LoggerHandle->RingBuffer, finalMessage, finalMessageLength);
    }
}
