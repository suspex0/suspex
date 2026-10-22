; BpTrapAsm.asm — v11 int1 (#DB) interception stub (ml64).
;
; Installed over every CPU's IDT[1] by SuspxBpTrapInstall (BpTrap.c).
; On entry the CPU pushed [RIP][CS][RFLAGS] plus [RSP][SS] when the hit
; came from CPL3 (non-KVAS hosts route user-mode #DBs through the kernel
; IDT too — the stub handles both frame shapes; CS.RPL decides swapgs).
;
; The stub snapshots the volatile regs, calls SuspxBpTrapDispatch, and:
;   * consumed (eax!=0): the C side already set RF in the frame's RFLAGS
;     (exec BPs re-fault on resume otherwise), restore regs and iretq.
;   * foreign (eax==0): restore regs and jmp the saved KiTrap01 — the
;     machine behaves exactly as if the hook weren't there.
;
; SuspxBpTrapInStub counts in-flight stubs so SuspxBpTrapUninstall can
; wait for the last dispatch to leave the image before restoring IDTs.

EXTERN SuspxBpTrapDispatch    : PROC
EXTERN SuspxBpTrapChainTarget : QWORD
EXTERN SuspxBpTrapInStub      : DWORD

.code

SuspxBpTrapStub PROC
    ; swap to kernel GS when the trap came from user mode
    test    byte ptr [rsp+8], 3         ; CS.RPL in the trap frame
    jz      short @@kentry
    swapgs
@@kentry:
    ; save volatiles (+ rbx as our nonvolatile scratch). After 8 pushes
    ; the CPU's trap frame sits at rsp+64: +0 RIP, +8 CS, +16 RFLAGS,
    ; (+24 RSP, +32 SS when the entry was from CPL3).
    push    rax
    push    rcx
    push    rdx
    push    rbx
    push    r8
    push    r9
    push    r10
    push    r11
    mov     rbx, rsp                    ; rbx -> push block; frame at rbx+64

    lock inc dword ptr [SuspxBpTrapInStub]

    and     rsp, -16                    ; ABI alignment for the call
    sub     rsp, 20h                    ; callee shadow space
    mov     rcx, [rbx+64]               ; arg1: faulting RIP
    mov     rdx, [rbx+72]               ; arg2: CS (kernel vs user entry)
    lea     r8,  [rbx+80]               ; arg3: &RFLAGS (C sets RF here)
    call    SuspxBpTrapDispatch
    mov     rsp, rbx                    ; unwind the aligned call frame
    lock dec dword ptr [SuspxBpTrapInStub]
    test    eax, eax
    jz      short @@chain

    ; consumed: record already queued, RF already set — resume.
    pop     r11
    pop     r10
    pop     r9
    pop     r8
    pop     rbx
    pop     rdx
    pop     rcx
    pop     rax
    test    byte ptr [rsp+8], 3         ; hand GS back on a user entry
    jz      short @@iret
    swapgs
@@iret:
    iretq

@@chain:
    ; not ours (single-step, foreign DRs, no subscription) — restore the
    ; pre-entry state and transfer to the saved handler.
    pop     r11
    pop     r10
    pop     r9
    pop     r8
    pop     rbx
    pop     rdx
    pop     rcx
    pop     rax
    test    byte ptr [rsp+8], 3
    jz      short @@jmp
    swapgs
@@jmp:
    jmp     qword ptr [SuspxBpTrapChainTarget]
SuspxBpTrapStub ENDP

END
