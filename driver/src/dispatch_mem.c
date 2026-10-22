#include "SuspexDriver.h"
#include "dispatch_internal.h"

#define SUSPEX_MAX_TRANSFER_BYTES (64ull * 1024 * 1024)

NTSTATUS SuspxHandleMemRead(_In_ WDFREQUEST Request, _In_ BOOLEAN Kernel, _In_ BOOLEAN Physical, _Out_ SIZE_T* Info)
{
    NTSTATUS st;
    SUSPEX_MEM_REQ req;
    PVOID in;
    SIZE_T inLen = 0, outLen = 0, size, done = 0;
    PVOID out;

    st = SuspxInput(Request, sizeof(req), &in, &inLen);
    if (!NT_SUCCESS(st)) {
        // Regression triage (v6): field report showed every MEM_READ
        // returning gle=87 while other IOCTLs worked. Log the failing
        // step + observed input length so the culprit is obvious in
        // the driver's own log.
        SuspxLog("MEMRD REJ k=%u p=%u SuspxInput st=%x inLen=%llx (want>=%llx)",
                 Kernel, Physical, st, (UINT64)inLen, (UINT64)sizeof(req));
        return st;
    }
    RtlCopyMemory(&req, in, sizeof(req));

    st = SuspxOutMdl(Request, &out, &outLen);
    if (!NT_SUCCESS(st)) {
        SuspxLog("MEMRD REJ k=%u p=%u SuspxOutMdl st=%x", Kernel, Physical, st);
        return st;
    }
    if (req.Size == 0 || req.Size > SUSPEX_MAX_TRANSFER_BYTES) {
        SuspxLog("MEMRD REJ k=%u p=%u req.Size=%llx (outLen=%llx flags=%x addr=%llx)",
                 Kernel, Physical, req.Size, (UINT64)outLen, req.Flags, req.Address);
        return STATUS_INVALID_PARAMETER;
    }
    size = (SIZE_T)req.Size < outLen ? (SIZE_T)req.Size : outLen;

    if (Physical) {
        st = SuspxPhysMemRead(req.Address, out, size, &done);
    } else if (Kernel) {
        // v6: pass Flags through raw — SuspxKernelMemRead now understands
        // both ALLOW_SOFTFAULT (v2) and PARTIAL (v6). Old-shape requests
        // (inLen < sizeof) get Flags=0, i.e. legacy strict semantics.
        UINT32 flags = 0;
        if (inLen >= sizeof(SUSPEX_MEM_REQ)) {
            flags = req.Flags;
        }
        st = SuspxKernelMemRead(req.Address, out, size, &done, flags);
    } else {
        st = SuspxUserMemRead(req.Pid, req.Address, out, size, &done);
    }
    SuspxLog("MEMRD k=%u p=%u pid=%llu addr=%llx size=%llx flags=%x inLen=%llx outLen=%llx -> st=%x n=%llx",
             Kernel, Physical, req.Pid, req.Address, req.Size,
             req.Flags, (UINT64)inLen, (UINT64)outLen, st, (UINT64)done);
    // v10.2: a partial read must complete STATUS_SUCCESS. Returning the
    // warning NTSTATUS STATUS_PARTIAL_COPY (0x8000000D) makes the I/O
    // manager fail the usermode DeviceIoControl (gle=299) and drop the
    // prefix entirely — callers saw a hard error instead of short data.
    // The valid-prefix signal survives in *Info (DeviceIoControl's
    // bytesReturned -> comm MemRead's got < len). Zero-byte results keep
    // propagating the real error (a SUCCESS with Info=0 would report a
    // bogus full read through comm's "ret ? ret : len").
    if (!NT_SUCCESS(st) && done > 0) {
        st = STATUS_SUCCESS;
    }
    *Info = done;
    return st;
}

NTSTATUS SuspxHandleMemWrite(_In_ WDFREQUEST Request, _In_ BOOLEAN Kernel, _In_ BOOLEAN Physical, _Out_ SIZE_T* Info)
{
    NTSTATUS st;
    SUSPEX_MEM_REQ req;
    SUSPEX_MEM_WRITE_IN ext;
    PVOID in, data, out = NULL;
    SIZE_T inLen, dataLen, size, done = 0, hdrLen, outLen = 0;
    UINT64 cr3 = 0;
    UINT32 flags2 = 0;
    UINT8 writePath = SUSPEX_MEM_WRITE_PATH_UNKNOWN;

    // METHOD_BUFFERED combined layout: [SUSPEX_MEM_REQ header][payload...]
    // v12: when the old Reserved slot carries SUSPEX_MEM_WRITE_EXT_MAGIC and
    // the input is >= sizeof(SUSPEX_MEM_WRITE_IN), the header is the 48-byte
    // ext form carrying Cr3+Flags2 and the payload sits at offset 48.
    st = SuspxInput(Request, sizeof(req), &in, &inLen);
    if (!NT_SUCCESS(st)) {
        return st;
    }
    RtlCopyMemory(&req, in, sizeof(req));
    hdrLen = sizeof(req);
    if (inLen >= sizeof(ext)) {
        RtlCopyMemory(&ext, in, sizeof(ext));
        if (ext.ExtLayout == SUSPEX_MEM_WRITE_EXT_MAGIC) {
            hdrLen = sizeof(ext);
            cr3 = ext.Cr3;
            flags2 = ext.Flags2;
        }
    }
    data = (PUCHAR)in + hdrLen;
    dataLen = inLen - hdrLen;
    if (req.Size == 0 || req.Size > SUSPEX_MAX_TRANSFER_BYTES) {
        return STATUS_INVALID_PARAMETER;
    }
    size = (SIZE_T)req.Size < dataLen ? (SIZE_T)req.Size : dataLen;

    // v12 reply channel: when the caller attached an output buffer the op
    // result goes out through SUSPEX_MEM_WRITE_OUT and the request itself
    // completes STATUS_SUCCESS — Done/WritePath then survive even a failed
    // write (v10.2 lesson: warning NTSTATUS breaks DeviceIoControl).
    if (!NT_SUCCESS(SuspxOutput(Request, sizeof(SUSPEX_MEM_WRITE_OUT), &out, &outLen))) {
        out = NULL;
    }

    if (cr3 && (Physical || !Kernel)) {
        // foreign-CR3 write only makes sense through the kernel-write
        // IOCTL — the cr3 defines the address space; a user/phys request
        // with cr3 set is a caller bug, not a degraded op.
        st = STATUS_INVALID_PARAMETER;
    } else if (Physical) {
        // v5: map-based physical write is opt-in (ALLOW_MAP_WRITE); refused
        // cleanly when the flag is missing.
        st = SuspxPhysMemWrite(req.Address, data, size, &done,
                               (req.Flags & SUSPEX_MEM_FLAG_ALLOW_MAP_WRITE) ? TRUE : FALSE);
        if (NT_SUCCESS(st)) {
            writePath = SUSPEX_MEM_WRITE_PATH_PHYS_REMAP;
        }
    } else if (Kernel) {
        st = SuspxKernelMemWrite(req.Address, data, size, &done, flags2, cr3, &writePath);
    } else {
        // user write goes through the target process — inherently a
        // linear-VA store; STRICT_VA/CR3 have no meaning here and are
        // ignored (user writes never had a remap fallback to refuse).
        st = SuspxUserMemWrite(req.Pid, req.Address, data, size, &done);
        if (NT_SUCCESS(st)) {
            writePath = SUSPEX_MEM_WRITE_PATH_DIRECT_VA;
        }
    }
    SuspxLog("MEMWR k=%u p=%u pid=%llu addr=%llx size=%llx cr3=%llx fl2=%x -> st=%x n=%llx path=%u",
             Kernel, Physical, req.Pid, req.Address, req.Size, cr3, flags2,
             st, (UINT64)done, writePath);

    if (out) {
        PSUSPEX_MEM_WRITE_OUT rep = (PSUSPEX_MEM_WRITE_OUT)out;
        rep->Status = (UINT32)st;
        rep->WritePath = writePath;
        rep->Reserved[0] = rep->Reserved[1] = rep->Reserved[2] = 0;
        rep->Done = (UINT64)done;
        *Info = sizeof(*rep);
        return STATUS_SUCCESS;
    }
    *Info = done;
    return st;
}

NTSTATUS SuspxInOut(_In_ WDFREQUEST Request, _In_ SIZE_T InSize, _In_ SIZE_T OutSize,
                    _Out_ PVOID* In, _Out_ PVOID* Out)
{
    NTSTATUS st;
    PVOID in, out;
    SIZE_T len;

    st = SuspxInput(Request, InSize, &in, &len);
    if (!NT_SUCCESS(st)) {
        return st;
    }
    st = SuspxOutput(Request, OutSize, &out, &len);
    if (!NT_SUCCESS(st)) {
        return st;
    }
    RtlCopyMemory(In, in, InSize);
    *Out = out;
    return STATUS_SUCCESS;
}

SIZE_T SuspxHandleAlloc(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status)
{
    SUSPEX_USER_ALLOC_IN in;
    PVOID out;
    SUSPEX_USER_ALLOC_OUT result;
    NTSTATUS st = SuspxInOut(Request, sizeof(in), sizeof(result), &in, &out);
    if (!NT_SUCCESS(st)) {
        *Status = st;
        return 0;
    }
    RtlZeroMemory(&result, sizeof(result));
    result.Status = (UINT32)SuspxUserAlloc(in.Pid, in.Size, in.Protect, &result.Address);
    RtlCopyMemory(out, &result, sizeof(result));
    SuspxLog("ALLOC pid=%llu size=%llx prot=%x -> st=%x addr=%llx",
             in.Pid, in.Size, in.Protect, result.Status, result.Address);
    *Status = STATUS_SUCCESS;
    return sizeof(result);
}

SIZE_T SuspxHandleFree(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status)
{
    SUSPEX_USER_FREE_IN in;
    PVOID out;
    SUSPEX_USER_FREE_OUT result;
    NTSTATUS st = SuspxInOut(Request, sizeof(in), sizeof(result), &in, &out);
    if (!NT_SUCCESS(st)) {
        *Status = st;
        return 0;
    }
    result.Status = (UINT32)SuspxUserFree(in.Pid, in.Address);
    result.Reserved = 0;
    RtlCopyMemory(out, &result, sizeof(result));
    SuspxLog("FREE pid=%llu addr=%llx -> st=%x", in.Pid, in.Address, result.Status);
    *Status = STATUS_SUCCESS;
    return sizeof(result);
}

SIZE_T SuspxHandleProtect(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status)
{
    SUSPEX_USER_PROTECT_IN in;
    PVOID out;
    SUSPEX_USER_PROTECT_OUT result;
    NTSTATUS st = SuspxInOut(Request, sizeof(in), sizeof(result), &in, &out);
    if (!NT_SUCCESS(st)) {
        *Status = st;
        return 0;
    }
    result.Status = (UINT32)SuspxUserProtect(in.Pid, in.Address, in.Size, in.Protect, &result.OldProtect);
    RtlCopyMemory(out, &result, sizeof(result));
    SuspxLog("PROT pid=%llu addr=%llx size=%llx -> st=%x old=%x",
             in.Pid, in.Address, in.Size, result.Status, result.OldProtect);
    *Status = STATUS_SUCCESS;
    return sizeof(result);
}

SIZE_T SuspxHandleKmemAlloc(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status)
{
    SUSPEX_KMEM_ALLOC_IN in;
    PVOID out;
    SUSPEX_KMEM_ALLOC_OUT result;
    NTSTATUS st = SuspxInOut(Request, sizeof(in), sizeof(result), &in, &out);
    if (!NT_SUCCESS(st)) {
        *Status = st;
        return 0;
    }
    RtlZeroMemory(&result, sizeof(result));
    result.Status = (UINT32)SuspxKmemAlloc(in.Size, &result.Address);
    RtlCopyMemory(out, &result, sizeof(result));
    SuspxLog("KALLOC size=%llx -> st=%x addr=%llx", in.Size, result.Status, result.Address);
    *Status = STATUS_SUCCESS;
    return sizeof(result);
}

SIZE_T SuspxHandleKmemFree(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status)
{
    SUSPEX_KMEM_FREE_IN in;
    PVOID out;
    SUSPEX_KMEM_FREE_OUT result;
    NTSTATUS st = SuspxInOut(Request, sizeof(in), sizeof(result), &in, &out);
    if (!NT_SUCCESS(st)) {
        *Status = st;
        return 0;
    }
    result.Status = (UINT32)SuspxKmemFree(in.Address);
    result.Reserved = 0;
    RtlCopyMemory(out, &result, sizeof(result));
    SuspxLog("KFREE addr=%llx -> st=%x", in.Address, result.Status);
    *Status = STATUS_SUCCESS;
    return sizeof(result);
}
