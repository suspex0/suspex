// v8 wedge-detector watchdog gRPC surface. Forwards to the driver via
// DriverMgr::Comm() (Driver::WatchdogArm/Kick/Disarm/List). No agent-side
// state — the source of truth is the driver's spinlock-protected table.
//
// If the driver isn't loaded (comm layer returns "gle=2" / "gle=6" — the
// device isn't there), we surface a clean "driver_absent" error the
// orchestrator's watchdog_manage tool can branch on.

#include <grpcpp/grpcpp.h>
#include <grpcpp/server_context.h>
#include "suspex.grpc.pb.h"

#include "services.hpp"

#include <string>

namespace suspex {

// Cheap "is the driver here?" — CreateFile against \\.\SuspexDrv. Called
// before every IOCTL forward so a driver-absent state gets a named error
// instead of a raw comm-layer gle=2/6 string.
static bool ProbeDriver(DriverMgr& drv, std::string* err)
{
    if (drv.Comm().IsOpen()) return true;
    // Try to open — this is a cheap CreateFile against \\.\SuspexDrv.
    if (!drv.Comm().Open()) {
        *err = "driver_absent: " + drv.Comm().LastError();
        return false;
    }
    return true;
}

class WatchdogSvc final : public Watchdog::Service {
public:
    WatchdogSvc(const AgentConfig& cfg, DriverMgr& drv) : cfg_(cfg), drv_(drv) {}

    grpc::Status Arm(::grpc::ServerContext* ctx, const WdgArmRequest* req,
                     WdgArmResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) return auth;
        std::string err;
        if (!ProbeDriver(drv_, &err)) {
            FillStatus(resp, err);
            return grpc::Status::OK;
        }
        if (!req->id() || req->deadline_ms() == 0) {
            FillStatus(resp, "watchdog arm: id and deadline_ms are required (id != 0)");
            return grpc::Status::OK;
        }
        std::string label = req->label();
        if (label.size() >= SUSPEX_WDG_MAX_LABEL) {
            label.resize(SUSPEX_WDG_MAX_LABEL - 1);
        }
        if (!drv_.Comm().WatchdogArm(req->id(), req->deadline_ms(),
                                      req->bugcheck_code(), req->flags(),
                                      req->cookie(), label)) {
            FillStatus(resp, drv_.Comm().LastError());
            return grpc::Status::OK;
        }
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

    grpc::Status Kick(::grpc::ServerContext* ctx, const WdgKickRequest* req,
                      WdgKickResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) return auth;
        std::string err;
        if (!ProbeDriver(drv_, &err)) {
            FillStatus(resp, err);
            return grpc::Status::OK;
        }
        if (!req->id()) {
            FillStatus(resp, "watchdog kick: id != 0 required");
            return grpc::Status::OK;
        }
        UINT64 kicks = 0, lastUs = 0, deadlineUs = 0;
        if (!drv_.Comm().WatchdogKick(req->id(), req->deadline_ms(), req->cookie(),
                                       &kicks, &lastUs, &deadlineUs)) {
            FillStatus(resp, drv_.Comm().LastError());
            return grpc::Status::OK;
        }
        resp->set_kick_count(kicks);
        resp->set_last_kick_us(lastUs);
        resp->set_deadline_us(deadlineUs);
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

    grpc::Status Disarm(::grpc::ServerContext* ctx, const WdgDisarmRequest* req,
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
        if (!req->id()) {
            resp->set_ok(false);
            resp->set_error("watchdog disarm: id != 0 required");
            return grpc::Status::OK;
        }
        if (!drv_.Comm().WatchdogDisarm(req->id())) {
            resp->set_ok(false);
            resp->set_error(drv_.Comm().LastError());
            return grpc::Status::OK;
        }
        resp->set_ok(true);
        return grpc::Status::OK;
    }

    grpc::Status List(::grpc::ServerContext* ctx, const WdgListRequest* /*req*/,
                      WdgListResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) return auth;
        std::string err;
        if (!ProbeDriver(drv_, &err)) {
            FillStatus(resp, err);
            return grpc::Status::OK;
        }
        std::vector<WatchdogEntry> entries;
        UINT64 nowUs = 0;
        if (!drv_.Comm().WatchdogList(entries, &nowUs)) {
            FillStatus(resp, drv_.Comm().LastError());
            return grpc::Status::OK;
        }
        resp->set_now_us(nowUs);
        for (auto& e : entries) {
            auto* out = resp->add_entries();
            out->set_id(e.Id);
            out->set_bugcheck_code(e.BugcheckCode);
            out->set_deadline_us(e.DeadlineUs);
            out->set_last_kick_us(e.LastKickUs);
            out->set_kick_count(e.KickCount);
            out->set_cookie(e.Cookie);
            out->set_armed_us(e.ArmedUs);
            out->set_label(e.Label);
            // Convert us -> ms for the LLM's convenience; keep the signed
            // remaining_ms so overdue entries (about to fire / just fired
            // ahead of a Disarm race) show up.
            int64_t rem_ms = e.RemainingUs / 1000;
            out->set_remaining_ms(rem_ms);
        }
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

private:
    const AgentConfig& cfg_;
    DriverMgr& drv_;
};

void RegisterWatchdogService(grpc::ServerBuilder& builder, const AgentConfig& cfg,
                             DriverMgr& drv)
{
    static WatchdogSvc svc(cfg, drv);
    builder.RegisterService(&svc);
}

} // namespace suspex
