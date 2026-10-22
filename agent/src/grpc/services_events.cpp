// v11 Events service — the agent's "ears". Forwards to the driver's notify
// ring via comm (NotifySubscribe/Read/Disable/Stats).
//
//   Stream — server-streaming drain loop: poll NOTIFY_READ every
//     interval_ms, emit chunks, honour duration/max_events/client cancel.
//     The `dropped` counter rides every chunk so the orchestrator can
//     report gaps honestly (never claims events were observed when the
//     ring overwrote them).
//   Poll   — one bounded drain (pull model for MCP tools).
//   Stats  — ring snapshot (buffered/dropped/seq + registered classes).
//
// Driver-absent surfaces as a named "driver_absent" error, matching the
// watchdog service convention.

#include <grpcpp/grpcpp.h>
#include <grpcpp/server_context.h>
#include "suspex.grpc.pb.h"

#include "services.hpp"

#include <algorithm>
#include <chrono>
#include <string>
#include <thread>
#include <vector>

namespace suspex {

namespace {

bool ProbeDriver(DriverMgr& drv, std::string* err)
{
    if (drv.Comm().IsOpen()) return true;
    if (!drv.Comm().Open()) {
        *err = "driver_absent: " + drv.Comm().LastError();
        return false;
    }
    return true;
}

std::string WideToUtf8Local(const std::wstring& w)
{
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(),
                                nullptr, 0, nullptr, nullptr);
    if (n <= 0) return {};
    std::string s((size_t)n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), &s[0], n,
                        nullptr, nullptr);
    return s;
}

void FillEvent(SuspexEvent* out, const SuspexEvent& e, UINT64 tsMs)
{
    *out = e;
    out->set_ts_ms(tsMs);
}

constexpr UINT32 EVENTS_MAX_INTERVAL_MS = 5000;
constexpr UINT32 EVENTS_MAX_DURATION_S = 3600;

// v12: kinds_mask is a bitmask over EventsKind values (bit = 1<<kind);
// the driver subscription is class-grained. The pre-v12 code passed the
// raw mask as classes, which silently mis-subscribed (e.g. a mask asking
// for proc kinds 1|2 read as classes 2|4 = image|thread). Translate here.
constexpr UINT32 KIND_BP_HIT_BIT = 1u << 6; // EVENTS_KIND_BP_HIT

UINT32 KindMaskToClasses(UINT32 mask, bool includeBp)
{
    if (!mask) {
        // "all" still excludes BP — the int1 hook is never implicit.
        return SUSPEX_EVT_CLASS_PROC | SUSPEX_EVT_CLASS_IMAGE
               | SUSPEX_EVT_CLASS_THREAD;
    }
    UINT32 c = 0;
    if (mask & ((1u << EVENTS_PROC_CREATE) | (1u << EVENTS_PROC_EXIT)))
        c |= SUSPEX_EVT_CLASS_PROC;
    if (mask & (1u << EVENTS_IMAGE_LOAD))
        c |= SUSPEX_EVT_CLASS_IMAGE;
    if (mask & ((1u << EVENTS_THREAD_CREATE) | (1u << EVENTS_THREAD_EXIT)))
        c |= SUSPEX_EVT_CLASS_THREAD;
    if (includeBp && (mask & KIND_BP_HIT_BIT))
        c |= SUSPEX_EVT_CLASS_BP;
    return c;
}

// Subscribe the requested classes. The BP class additionally needs the
// caller's dangerous_ok (it installs the driver's int1 hook); a refused
// or failed BP subscribe reports through `err`.
bool EnsureSubscribed(DriverMgr& drv, UINT32 kindsMask, bool dangerousOk,
                      UINT32* registered, std::string* err)
{
    const bool wantBp = (kindsMask & KIND_BP_HIT_BIT) != 0;
    if (wantBp && !dangerousOk) {
        *err = "bp_hook_refused: kinds_mask bit 6 (BP_HIT) installs the "
               "driver int1 hook — resend with dangerous_ok=true "
               "(PatchGuard-sensitive, lab-only)";
        return false;
    }
    UINT32 classes = KindMaskToClasses(kindsMask, /*includeBp=*/wantBp);
    if (!classes) {
        return true; // nothing to register
    }
    UINT32 flags = wantBp ? SUSPEX_NOTIFY_FLAG_BP_HOOK_OK : 0;
    if (!drv.Comm().NotifySubscribe(classes, flags, registered)) {
        *err = drv.Comm().LastError();
        return false;
    }
    if (wantBp && !(*registered & SUSPEX_EVT_CLASS_BP)) {
        *err = "bp_hook_failed: driver did not register the BP class "
               "(HVCI on? see agent log / BPTRAP lines)";
        return false;
    }
    return true;
}

void FillSuspexEvent(SuspexEvent* ev, const SuspexEventRec& e, UINT64 ts,
                     UINT64 dropped, UINT64 lastDropped)
{
    ev->set_seq(e.Seq);
    ev->set_ts_ms(ts);
    ev->set_kind(static_cast<EventsKind>(e.Kind));
    ev->set_pid(e.Pid);
    ev->set_parent_pid(e.ParentPid);
    ev->set_tid(e.Tid);
    ev->set_image(WideToUtf8Local(e.Image));
    ev->set_dropped(dropped > lastDropped);
    // v12 BP_HIT payload
    ev->set_address(e.Address);
    ev->set_dr6(e.Dr6);
    ev->set_bp_id(e.BpId);
    ev->set_slot(e.Slot);
    ev->set_access(e.Access);
    ev->set_irql(e.Irql);
}

} // namespace

class EventsSvc final : public Events::Service {
public:
    EventsSvc(const AgentConfig& cfg, DriverMgr& drv) : cfg_(cfg), drv_(drv) {}

    grpc::Status Stream(::grpc::ServerContext* ctx,
                        const EventsStreamRequest* req,
                        grpc::ServerWriter<EventsStreamChunk>* writer) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) return auth;

        std::string err;
        if (!ProbeDriver(drv_, &err)) {
            EventsStreamChunk c;
            FillStatus(&c, err);
            c.set_done(true);
            writer->Write(c);
            return grpc::Status::OK;
        }

        // v12: translate the kinds bitmask to driver classes (fixes the
        // raw-mask passthrough) and handle the BP class — subscribing it
        // installs the driver's int1 hook, gated by dangerous_ok.
        UINT32 registered = 0;
        std::string subErr;
        if (!EnsureSubscribed(drv_, req->kinds_mask(), req->dangerous_ok(),
                              &registered, &subErr)) {
            EventsStreamChunk c;
            FillStatus(&c, subErr);
            c.set_done(true);
            writer->Write(c);
            return grpc::Status::OK;
        }

        const UINT32 interval = req->interval_ms() ? std::min(req->interval_ms(), EVENTS_MAX_INTERVAL_MS) : 250;
        const UINT32 durationS = std::min(req->duration_s(), EVENTS_MAX_DURATION_S);
        const UINT32 intervalMs = req->interval_ms() ? std::min(req->interval_ms(), EVENTS_MAX_INTERVAL_MS) : 250;
        const UINT64 maxEvents = req->max_events();
        auto deadline = std::chrono::steady_clock::now()
                        + std::chrono::seconds(durationS ? durationS : EVENTS_MAX_DURATION_S);
        UINT64 sent = 0;
        UINT64 lastDropped = 0;

        while (true) {
            if (ctx->IsCancelled()) break;
            if (durationS && std::chrono::steady_clock::now() > deadline) break;

            std::vector<SuspexEventRec> batch;
            UINT64 dropped = 0, lastSeq = 0;
            if (!drv_.Comm().NotifyRead(512, batch, &dropped, &lastSeq)) {
                break;
            }

            if (!batch.empty()) {
                EventsStreamChunk c;
                auto ts = (UINT64)std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count();
                for (auto& e : batch) {
                    if (req->kinds_mask() && !(req->kinds_mask() & (1u << e.Kind))) {
                        continue;
                    }
                    auto* ev = c.add_events();
                    FillSuspexEvent(ev, e, ts, dropped, lastDropped);
                }
                lastDropped = dropped;
                c.set_dropped(dropped);
                c.mutable_status()->set_ok(true);
                if (!writer->Write(c)) break;
                sent += batch.size();
                if (maxEvents && sent >= maxEvents) break;
            } else {
                // keepalive chunk so the client can observe liveness + drops
                EventsStreamChunk c;
                c.mutable_status()->set_ok(true);
                c.set_dropped(dropped);
                c.set_done(false);
                if (!writer->Write(c)) break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(intervalMs));
        }

        EventsStreamChunk done;
        done.mutable_status()->set_ok(true);
        done.set_done(true);
        done.set_dropped(lastDropped);
        writer->Write(done);
        return grpc::Status::OK;
    }

    grpc::Status Poll(::grpc::ServerContext* ctx, const EventsPollRequest* req,
                      EventsPollResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) return auth;
        std::string err;
        if (!ProbeDriver(drv_, &err)) {
            FillStatus(resp, err);
            return grpc::Status::OK;
        }
        // v12: the BP class is installed on demand — a poll with the
        // BP_HIT bit first subscribes it (int1 hook; needs dangerous_ok),
        // then drains. Other bits in kinds_mask act as an output filter
        // only — Poll stays a pure reader for the notify classes.
        if (req->kinds_mask() & KIND_BP_HIT_BIT) {
            UINT32 registered = 0;
            std::string subErr;
            if (!EnsureSubscribed(drv_, KIND_BP_HIT_BIT,
                                  req->dangerous_ok(), &registered, &subErr)) {
                FillStatus(resp, subErr);
                return grpc::Status::OK;
            }
        }
        std::vector<SuspexEventRec> batch;
        UINT64 dropped = 0, lastSeq = 0;
        if (!drv_.Comm().NotifyRead(req->max_events() ? req->max_events() : 256,
                                    batch, &dropped, &lastSeq)) {
            FillStatus(resp, drv_.Comm().LastError());
            return grpc::Status::OK;
        }
        auto ts = (UINT64)std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        for (auto& e : batch) {
            if (req->kinds_mask() && !(req->kinds_mask() & (1u << e.Kind))) {
                continue;
            }
            auto* ev = resp->add_events();
            FillSuspexEvent(ev, e, ts, dropped, 0);
        }
        resp->set_last_seq(lastSeq);
        resp->set_dropped(dropped);
        SuspexNotifyStats st{};
        if (drv_.Comm().NotifyStats(&st)) {
            resp->set_subscribed(st.Registered != 0);
            resp->set_bp_hook((st.Registered & SUSPEX_EVT_CLASS_BP) != 0);
        }
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

    grpc::Status Stats(::grpc::ServerContext* ctx, const EventsStatsRequest* req,
                       EventsStatsResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) return auth;
        std::string err;
        if (!ProbeDriver(drv_, &err)) {
            FillStatus(resp, err);
            return grpc::Status::OK;
        }
        SuspexNotifyStats st{};
        if (!drv_.Comm().NotifyStats(&st)) {
            FillStatus(resp, drv_.Comm().LastError());
            return grpc::Status::OK;
        }
        resp->set_buffered(st.Buffered);
        resp->set_dropped(st.Dropped);
        resp->set_seq(st.Seq);
        resp->set_proc_notify((st.Registered & SUSPEX_EVT_CLASS_PROC) != 0);
        resp->set_image_notify((st.Registered & SUSPEX_EVT_CLASS_IMAGE) != 0);
        resp->set_thread_notify((st.Registered & SUSPEX_EVT_CLASS_THREAD) != 0);
        // v12: CLASS_BP registered == int1 hook installed
        resp->set_bp_hook((st.Registered & SUSPEX_EVT_CLASS_BP) != 0);
        resp->set_bp_missed(st.BpTrapMissed);
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

    grpc::Status Disable(::grpc::ServerContext* ctx, const OpStatus* req,
                         OpStatus* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) return auth;
        std::string err;
        if (!ProbeDriver(drv_, &err)) {
            resp->set_ok(false);
            resp->set_error(err);
            return grpc::Status::OK;
        }
        UINT32 registered = 0;
        if (!drv_.Comm().NotifyDisable(&registered)) {
            resp->set_ok(false);
            resp->set_error(drv_.Comm().LastError());
            return grpc::Status::OK;
        }
        resp->set_ok(true);
        return grpc::Status::OK;
    }

private:
    const AgentConfig& cfg_;
    DriverMgr& drv_;
};

void RegisterEventsService(grpc::ServerBuilder& builder, const AgentConfig& cfg,
                           DriverMgr& drv)
{
    static EventsSvc svc(cfg, drv);
    builder.RegisterService(&svc);
}

} // namespace suspex
