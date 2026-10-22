// drv_exerciser kcall — synchronous kernel function call (ABI v13).
#include "exerciser_common.hpp"

using namespace suspex;

int CmdKcall(UINT64 target, const std::vector<UINT64>& args, UINT32 timeoutMs, bool force)
{
    SUSPEX_KERNEL_CALL_IN in = {};
    SUSPEX_KERNEL_CALL_OUT out = {};
    in.Target = target;
    in.Argc = (UINT32)args.size();
    if (in.Argc > SUSPEX_KC_MAX_ARGS) {
        printf("FAIL kcall: argc=%u > %d\n", (unsigned)in.Argc, SUSPEX_KC_MAX_ARGS);
        return 1;
    }
    for (size_t i = 0; i < args.size(); ++i) {
        in.Args[i] = args[i];
    }
    in.TimeoutMs = timeoutMs;
    in.Flags = force ? SUSPEX_KC_FLAG_FORCE : 0;
    if (!g_drv.KernelCall(in, &out)) {
        printf("FAIL kcall: %s\n", g_drv.LastError().c_str());
        return 1;
    }
    printf("PASS kcall st=%x done=%u ex=%u excode=%x ret=%llx\n",
           (unsigned)out.Status, (unsigned)out.Completed, (unsigned)out.Exception,
           (unsigned)out.ExceptionCode, (unsigned long long)out.ReturnValue);
    return 0;
}