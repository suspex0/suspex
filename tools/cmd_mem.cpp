// Memory / process / VAD / handle / kalloc / rcall commands. Split from
// drv_exerciser.cpp (phase 7d). No logic changes.

#include "exerciser_common.hpp"

using namespace suspex;

static void PrintModuleList(std::vector<ModuleEntry>& mods)
{
    printf("%zu modules\n", mods.size());
    size_t n = mods.size() < 10 ? mods.size() : 10;
    for (size_t i = 0; i < n; i++) {
        wprintf(L"  %p %8llx %s\n", (void*)(uintptr_t)mods[i].Base,
                (unsigned long long)mods[i].Size, mods[i].Name.c_str());
    }
    if (mods.size() > n) {
        printf("  ... %zu more\n", mods.size() - n);
    }
}

int CmdPing()
{
    PingInfo p{};
    if (!g_drv.Ping(&p)) {
        printf("FAIL ping: %s\n", g_drv.LastError().c_str());
        return 1;
    }
    printf("PASS ping v%u.%u abi=%u build=%u flags=%c%c%c%c\n",
           p.VersionMajor, p.VersionMinor, p.AbiVersion, p.NtBuild,
           (p.Flags & SUSPEX_FLAG_TESTSIGNING) ? 'T' : '-',
           (p.Flags & SUSPEX_FLAG_HVCI) ? 'H' : '-',
           (p.Flags & SUSPEX_FLAG_SECUREBOOT) ? 'S' : '-',
           (p.Flags & SUSPEX_FLAG_KERNEL_DEBUGGER) ? 'D' : '-');
    return 0;
}

int CmdSelftest()
{
    const size_t kSize = 4096;
    unsigned char pattern[64], back[64];
    for (int i = 0; i < 64; i++) {
        pattern[i] = (unsigned char)(i ^ 0x5A);
    }
    UINT64 addr = 0;

    if (!g_drv.UserAlloc(GetCurrentProcessId(), kSize, PAGE_READWRITE, &addr)) {
        printf("FAIL selftest alloc: %s\n", g_drv.LastError().c_str());
        return 1;
    }
    printf("  alloc -> %llx\n", (unsigned long long)addr);

    SIZE_T w = 0, r = 0;
    if (!g_drv.MemWrite(Space::User, GetCurrentProcessId(), addr, pattern, sizeof(pattern), &w) ||
        !g_drv.MemRead(Space::User, GetCurrentProcessId(), addr, back, sizeof(back), &r)) {
        printf("FAIL selftest rw: %s\n", g_drv.LastError().c_str());
        return 1;
    }
    if (memcmp(pattern, back, sizeof(pattern)) != 0) {
        printf("FAIL selftest readback mismatch\n");
        return 1;
    }
    UINT32 oldProt = 0;
    if (!g_drv.UserProtect(GetCurrentProcessId(), addr, 64, PAGE_READONLY, &oldProt)) {
        printf("FAIL selftest protect: %s\n", g_drv.LastError().c_str());
        return 1;
    }
    printf("  protect old=%x\n", oldProt);
    g_drv.UserProtect(GetCurrentProcessId(), addr, 64, PAGE_READWRITE, &oldProt);

    if (!g_drv.UserFree(GetCurrentProcessId(), addr)) {
        printf("FAIL selftest free: %s\n", g_drv.LastError().c_str());
        return 1;
    }
    printf("PASS selftest (alloc/write/read/protect/free roundtrip)\n");
    return 0;
}

int CmdMemRead(Space space, UINT32 pid, UINT64 addr, UINT64 size)
{
    std::vector<unsigned char> buf((size_t)size);
    SIZE_T got = 0;
    if (!g_drv.MemRead(space, pid, addr, buf.data(), buf.size(), &got)) {
        printf("FAIL memread: %s\n", g_drv.LastError().c_str());
        return 1;
    }
    printf("PASS memread %llu bytes @ %llx\n", (unsigned long long)got, (unsigned long long)addr);
    size_t n = buf.size() < 32 ? buf.size() : 32;
    for (size_t i = 0; i < n; i++) {
        printf("%02x ", buf[i]);
    }
    printf("\n");
    return 0;
}

int CmdMemWrite(Space space, UINT32 pid, UINT64 addr, const std::string& hex)
{
    std::vector<unsigned char> buf;
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        buf.push_back((unsigned char)strtoul(hex.substr(i, 2).c_str(), nullptr, 16));
    }
    SIZE_T w = 0;
    if (!g_drv.MemWrite(space, pid, addr, buf.data(), buf.size(), &w)) {
        printf("FAIL memwrite: %s\n", g_drv.LastError().c_str());
        return 1;
    }
    printf("PASS memwrite %llu bytes @ %llx\n", (unsigned long long)w, (unsigned long long)addr);
    return 0;
}

int CmdProcs()
{
    std::vector<ProcessEntry> procs;
    if (!g_drv.ProcessList(procs)) {
        printf("FAIL procs: %s\n", g_drv.LastError().c_str());
        return 1;
    }
    printf("%zu processes\n", procs.size());
    size_t n = procs.size() < 12 ? procs.size() : 12;
    for (size_t i = 0; i < n; i++) {
        wprintf(L"  %6u (ppid %6u) %s\n", procs[i].Pid, procs[i].ParentPid, procs[i].ImageName.c_str());
    }
    if (procs.size() > n) {
        printf("  ... %zu more\n", procs.size() - n);
    }
    printf("PASS procs\n");
    return 0;
}

int CmdMods(bool kernel, UINT32 pid, bool wow64)
{
    std::vector<ModuleEntry> mods;
    bool ok = kernel ? g_drv.KernelModules(mods) : g_drv.UserModules(pid, mods, wow64);
    if (!ok) {
        printf("FAIL mods: %s\n", g_drv.LastError().c_str());
        return 1;
    }
    PrintModuleList(mods);
    printf("PASS mods %s%s\n", kernel ? "kernel" : "user", wow64 ? " (wow64)" : "");
    return 0;
}

int CmdPhysOob()
{
    // range check must reject a wrapping [Pa, Pa+Len) instead of BSODing in
    // MmMapIoSpace on a bogus physical address
    unsigned char buf[8];
    SIZE_T got = 0;
    if (g_drv.MemRead(Space::Physical, 0, 0xFFFFFFFFFFFFF000ull, buf, 0x2000, &got)) {
        printf("FAIL phys_oob: wrap-around range was accepted\n");
        return 1;
    }
    printf("PASS phys_oob (wrap rejected: %s)\n", g_drv.LastError().c_str());
    return 0;
}

// v5 gate: ABI-5 physical write. Allocates OUR OWN nonpaged pool, translates
// the kernel VA to its physical backing, then proves the full C.1 chain:
//   opt-out refusal -> opt-in map write -> physical read-back -> kernel-VA
//   read-back agree. Never touches physical memory we don't own.
int CmdPhysWrVerify()
{
    const size_t kSize = 0x1000;
    unsigned char patA[64], patB[64], back[64];
    for (int i = 0; i < 64; i++) {
        patA[i] = (unsigned char)(i ^ 0xA5);
        patB[i] = (unsigned char)(i ^ 0x3C);
    }
    UINT64 kva = 0, pa = 0;
    SIZE_T w = 0, r = 0;

    if (!g_drv.KmemAlloc(kSize, &kva)) {
        printf("FAIL physwr-verify kalloc: %s\n", g_drv.LastError().c_str());
        return 1;
    }
    if (!g_drv.MemWrite(Space::Kernel, 0, kva, patA, sizeof(patA), &w)) {
        printf("FAIL physwr-verify kernel seed write: %s\n", g_drv.LastError().c_str());
        goto fail;
    }
    if (!g_drv.VaTranslate(kva, &pa)) {
        printf("FAIL physwr-verify vatrans: %s\n", g_drv.LastError().c_str());
        goto fail;
    }
    printf("  kva %llx -> pa %llx\n", (unsigned long long)kva, (unsigned long long)pa);

    if (!g_drv.MemRead(Space::Physical, 0, pa, back, sizeof(back), &r) || memcmp(back, patA, 64) != 0) {
        printf("FAIL physwr-verify: physical read-back of seeded page mismatched\n");
        goto fail;
    }

    // negative: without ALLOW_MAP_WRITE the v5 driver must refuse
    if (g_drv.MemWrite(Space::Physical, 0, pa, patB, sizeof(patB), &w, 0)) {
        printf("FAIL physwr-verify: write WITHOUT allow_map_write was accepted\n");
        goto fail;
    }
    printf("  un-flagged write refused: %s\n", g_drv.LastError().c_str());

    if (!g_drv.MemWrite(Space::Physical, 0, pa, patB, sizeof(patB), &w, SUSPEX_MEM_FLAG_ALLOW_MAP_WRITE)
        || w != sizeof(patB)) {
        printf("FAIL physwr-verify: flagged map write failed: %s\n", g_drv.LastError().c_str());
        goto fail;
    }
    if (!g_drv.MemRead(Space::Physical, 0, pa, back, sizeof(back), &r) || memcmp(back, patB, 64) != 0) {
        printf("FAIL physwr-verify: physical read-back after map write mismatched\n");
        goto fail;
    }
    if (!g_drv.MemRead(Space::Kernel, 0, kva, back, sizeof(back), &r) || memcmp(back, patB, 64) != 0) {
        printf("FAIL physwr-verify: kernel-VA view after map write mismatched (wrong PA?)\n");
        goto fail;
    }
    if (!g_drv.KmemFree(kva)) {
        printf("FAIL physwr-verify kfree: %s\n", g_drv.LastError().c_str());
        return 1;
    }
    printf("PASS physwr-verify (opt-in refusal, map write, phys+VA read-back)\n");
    return 0;

fail:
    g_drv.KmemFree(kva);
    return 1;
}

int CmdVaTranslate(UINT64 va)
{
    UINT64 pa = 0;
    if (!g_drv.VaTranslate(va, &pa)) {
        printf("FAIL vatrans: %s\n", g_drv.LastError().c_str());
        return 1;
    }
    printf("PASS vatrans va=%llx -> pa=%llx\n", (unsigned long long)va, (unsigned long long)pa);
    return 0;
}

int CmdVad(UINT32 pid)
{
    std::vector<VadRecord> vads;
    if (!g_drv.VadList(pid, vads)) {
        printf("FAIL vad: %s\n", g_drv.LastError().c_str());
        return 1;
    }
    printf("%zu VADs\n", vads.size());
    size_t n = vads.size() < 10 ? vads.size() : 10;
    for (size_t i = 0; i < n; i++) {
        printf("  %012llx-%012llx %08x type=%u\n",
               (unsigned long long)vads[i].Start, (unsigned long long)vads[i].End,
               vads[i].Protect, vads[i].VadType);
    }
    if (vads.size() > n) {
        printf("  ... %zu more\n", vads.size() - n);
    }
    printf("PASS vad pid=%u\n", pid);
    return 0;
}

int CmdHandles(UINT32 pid, bool names)
{
    std::vector<HandleRecord> handles;
    if (!g_drv.HandleList(pid, handles, names)) {
        printf("FAIL handles: %s\n", g_drv.LastError().c_str());
        return 1;
    }
    printf("%zu handles\n", handles.size());
    size_t n = handles.size() < 12 ? handles.size() : 12;
    for (size_t i = 0; i < n; i++) {
        wprintf(L"  h=%04llx %s obj=%llx %s\n",
                (unsigned long long)handles[i].Handle, handles[i].TypeName.c_str(),
                (unsigned long long)handles[i].Object, handles[i].Name.c_str());
    }
    if (handles.size() > n) {
        printf("  ... %zu more\n", handles.size() - n);
    }
    printf("PASS handles pid=%u names=%d\n", pid, names ? 1 : 0);
    return 0;
}

int CmdKAlloc(UINT64 size, bool free, UINT64 addr)
{
    if (!free) {
        UINT64 a = 0;
        if (!g_drv.KmemAlloc(size, &a)) {
            printf("FAIL kalloc: %s\n", g_drv.LastError().c_str());
            return 1;
        }
        printf("PASS kalloc %llx\n", (unsigned long long)a);
        return 0;
    }
    if (!g_drv.KmemFree(addr)) {
        printf("FAIL kfree: %s\n", g_drv.LastError().c_str());
        return 1;
    }
    printf("PASS kfree %llx\n", (unsigned long long)addr);
    return 0;
}

int CmdRcall(UINT32 pid, UINT64 tid, UINT64 target, bool kernelMode)
{
    bool queued = false, alerted = false;
    if (!g_drv.RemoteCall(pid, tid, target, 0, 0, 0, kernelMode ? SUSPEX_RC_FLAG_KERNEL : 0,
                          &queued, &alerted)) {
        printf("FAIL rcall: %s\n", g_drv.LastError().c_str());
        return 1;
    }
    printf("PASS rcall queued=%d alerted=%d\n", queued, alerted);
    return 0;
}
