#include <grpcpp/grpcpp.h>
#include <grpcpp/server_context.h>
#include <grpcpp/support/sync_stream.h>
#include "suspex.grpc.pb.h"

#include <algorithm>
#include <functional>
#include "services.hpp"
#include "../common.h"
#include "../dump/dumper.hpp"
#include "../files.hpp"
#include "../log_ring.hpp"
#include "../exec/detached.hpp"

#include <filesystem>
#include <fstream>

namespace suspex {

// -------------------------------------------------------------- Files svc ----

class FilesSvc final : public Files::Service {
public:
    FilesSvc(const AgentConfig& cfg, DriverMgr& drv, std::reference_wrapper<ExecMgr> execRef)
        : cfg_(cfg), drv_(drv), execRef_(execRef) {}

    grpc::Status Upload(::grpc::ServerContext* ctx, grpc::ServerReader<UploadChunk>* reader, UploadResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        UploadChunk chunk;
        std::wstring path;
        UINT64 total = 0, written = 0;
        Sha256 sha;
        std::string hashErr;
        std::ofstream out;
        std::wstring tmp;
        while (reader->Read(&chunk)) {
            switch (chunk.payload_case()) {
            case UploadChunk::kHeader:
                path = Utf8ToWide(chunk.header().path());
                total = chunk.header().size();
                if (total > cfg_.maxTransferBytes) {
                    FillStatus(resp, "upload exceeds max_transfer_mb");
                    return grpc::Status::OK;
                }
                if (!sha.Begin(&hashErr)) {
                    FillStatus(resp, hashErr);
                    return grpc::Status::OK;
                }
                tmp = path + L".suspex_tmp";
                out.open(tmp, std::ios::binary | std::ios::trunc);
                if (!out) {
                    FillStatus(resp, "cannot open temp file for write");
                    return grpc::Status::OK;
                }
                break;
            case UploadChunk::kData:
                if (!out) {
                    FillStatus(resp, "data chunk before header");
                    return grpc::Status::OK;
                }
                out.write(chunk.data().data(), (std::streamsize)chunk.data().size());
                sha.Update(chunk.data().data(), chunk.data().size());
                written += chunk.data().size();
                break;
            default:
                break;
            }
        }
        if (!out) {
            FillStatus(resp, "no upload header received");
            return grpc::Status::OK;
        }
        out.close();
        std::string digest = sha.FinishHex();
        if (!MoveFileExW(tmp.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING)) {
            FillStatus(resp, Win32ErrorString("MoveFileEx", GetLastError()));
            return grpc::Status::OK;
        }
        resp->set_path(WideToUtf8(path));
        resp->set_sha256(digest);
        resp->set_bytes_written(written);
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

    grpc::Status Download(::grpc::ServerContext* ctx, const DownloadRequest* req,
                          grpc::ServerWriter<DownloadChunk>* writer) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        std::wstring path = Utf8ToWide(req->path());
        DWORD open_gle = 0;
        HANDLE h = OpenForReadEx(path, &open_gle);
        // v14: share-mode-0 lock → VSS shadow copy. The streamed bytes are a
        // point-in-time snapshot; via_snapshot on the header says so.
        std::wstring shadow;
        bool via_snapshot = false;
        if (h == INVALID_HANDLE_VALUE && IsSharingGle(open_gle)) {
            std::string verr;
            if (LockedCopyViaVss(path, &shadow, &verr)) {
                DWORD g2 = 0;
                h = OpenForReadEx(shadow, &g2);
                via_snapshot = (h != INVALID_HANDLE_VALUE);
            }
        }
        if (h == INVALID_HANDLE_VALUE) {
            if (!shadow.empty()) {
                DeleteFileW(shadow.c_str());
            }
            return grpc::Status(grpc::StatusCode::NOT_FOUND,
                                Win32ErrorString("open for download", open_gle));
        }
        struct TmpCleanup {
            const std::wstring& p;
            ~TmpCleanup() { if (!p.empty()) DeleteFileW(p.c_str()); }
        } tmp_guard{shadow};

        LARGE_INTEGER size_li{};
        GetFileSizeEx(h, &size_li);
        UINT64 size = (UINT64)size_li.QuadPart;
        LARGE_INTEGER off{};
        off.QuadPart = (LONGLONG)req->offset();
        SetFilePointerEx(h, off, nullptr, FILE_BEGIN);
        UINT64 len = req->length() ? req->length() : size - req->offset();

        DownloadChunk hdr;
        hdr.mutable_header()->set_size(size);
        // Hash the same bytes we stream — the shadow file when locked, not
        // a second snapshot.
        hdr.mutable_header()->set_sha256(
            Sha256HexFile(via_snapshot ? shadow : path));
        hdr.mutable_header()->set_via_snapshot(via_snapshot);
        writer->Write(hdr);

        std::vector<char> buf(64 * 1024);
        UINT64 sent = 0;
        while (sent < len && !ctx->IsCancelled()) {
            DWORD want = (DWORD)(std::min)((UINT64)buf.size(), len - sent);
            DWORD got = 0;
            if (!ReadFile(h, buf.data(), want, &got, nullptr) || !got) {
                break;
            }
            DownloadChunk c;
            c.set_data(buf.data(), (size_t)got);
            writer->Write(c);
            sent += (UINT64)got;
        }
        CloseHandle(h);
        return grpc::Status::OK;
    }

    grpc::Status DumpModule(::grpc::ServerContext* ctx, const DumpModuleRequest* req,
                            grpc::ServerWriter<DownloadChunk>* writer) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        const bool kernelDump = req->kernel();
        if (kernelDump && !drv_.Comm().Open()) {
            return grpc::Status(grpc::StatusCode::FAILED_PRECONDITION,
                                "kernel module dump requires the driver "
                                "(target_manage driver_load first)");
        }
        // quiesce: suspend the target around enumeration + read so the image
        // is coherent (pairs with bp-hit workflows); RAII resume. User-mode
        // only — there is no process to suspend for a kernel dump.
        std::string suspendErr;
        bool suspended = false;
        if (!kernelDump && req->quiesce() && req->pid() &&
            req->pid() != GetCurrentProcessId()) {
            suspendErr = execRef_.get().Suspend(req->pid());
            suspended = suspendErr.empty();
        }
        struct ResumeGuard {
            std::reference_wrapper<ExecMgr> exec;
            UINT32 pid;
            bool armed;
            ~ResumeGuard()
            {
                if (armed) {
                    exec.get().Resume(pid);
                }
            }
        } guard{execRef_, req->pid(), suspended};

        std::vector<suspex::ModuleEntry> mods;
        bool listed = kernelDump ? drv_.Comm().KernelModules(mods)
                                 : ListUserModules(&drv_, req->pid(), &mods);
        if (!listed) {
            return grpc::Status(grpc::StatusCode::FAILED_PRECONDITION,
                                suspendErr.empty()
                                    ? "module enumeration failed: " + drv_.Comm().LastError()
                                    : "suspend failed: " + suspendErr);
        }
        UINT64 base = FindModuleBase(mods, req->module());
        if (!base) {
            return grpc::Status(grpc::StatusCode::NOT_FOUND,
                                "module not found: " + req->module());
        }
        MemReaderCtx rctx{&drv_};
        ModuleDumper::DumpType type = req->dump_type() == "unrelocated"
                                          ? ModuleDumper::DUMP_UNRELOCATED
                                          : ModuleDumper::DUMP_AS_LOADED;
        auto result = kernelDump
                          ? ModuleDumper::Dump(&rctx, &KernelMemReadFn, 0, base, type)
                          : ModuleDumper::Dump(&rctx, &UserMemReadFn, req->pid(), base, type);
        if (!result.error.empty()) {
            return grpc::Status(grpc::StatusCode::INTERNAL, result.error);
        }
        DownloadChunk hdr;
        hdr.mutable_header()->set_size(result.image.size());
        hdr.mutable_header()->set_sha256(result.sha256);
        hdr.mutable_header()->set_notes(result.notes);
        // v0.24: per-section residency map — the orchestrator surfaces this
        // so zeroed PAGE/INIT tails are explicit instead of silent.
        for (const auto& s : result.sections) {
            DumpedSection* row = hdr.mutable_header()->add_sections();
            row->set_name(s.name);
            row->set_va(s.va);
            row->set_size(s.size);
            row->set_dumped_bytes(s.dumped_bytes);
            row->set_complete(s.complete);
        }
        writer->Write(hdr);

        const size_t kChunk = 64 * 1024;
        for (size_t off = 0; off < result.image.size(); off += kChunk) {
            if (ctx->IsCancelled()) {
                break;
            }
            size_t n = (std::min)(kChunk, result.image.size() - off);
            DownloadChunk c;
            c.set_data(result.image.data() + off, n);
            writer->Write(c);
        }
        return grpc::Status::OK;
    }

    grpc::Status Hash(::grpc::ServerContext* ctx, const HashRequest* req, HashResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        std::wstring path = Utf8ToWide(req->path());
        std::error_code ec;
        auto sz = std::filesystem::file_size(path, ec);
        if (ec) {
            FillStatus(resp, "cannot stat file: " + ec.message());
            return grpc::Status::OK;
        }
        // v14: gle-typed hash. The old "hash failed" ate the Win32 error,
        // so a locked file looked identical to a missing one. Sharing
        // violations take the VSS snapshot path inside Sha256HexFile.
        DWORD gle = 0;
        bool via_snapshot = false;
        std::string digest = Sha256HexFile(path, &gle, &via_snapshot);
        if (digest.empty()) {
            std::string e = Win32ErrorString("open for hash", gle);
            if (IsSharingGle(gle)) {
                e = "sharing_locked: " + e +
                    " — live file is share-mode-0; VSS fallback also failed";
            }
            FillStatus(resp, e);
            return grpc::Status::OK;
        }
        resp->set_sha256(digest);
        resp->set_size(sz);
        resp->set_via_snapshot(via_snapshot);
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

    grpc::Status ListDir(::grpc::ServerContext* ctx, const ListDirRequest* req, ListDirResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        std::vector<FileEntry> entries;
        std::string err;
        if (!ListDirTree(Utf8ToWide(req->path()), req->recursive(),
                         req->max_entries() ? req->max_entries() : 2000, &entries, &err)) {
            FillStatus(resp, err);
            return grpc::Status::OK;
        }
        for (auto& e : entries) {
            auto* de = resp->add_entries();
            de->set_name(WideToUtf8(e.path));
            de->set_dir(e.isDir);
            de->set_size(e.size);
            de->set_mtime_unix(e.mtimeUnix);
        }
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

    grpc::Status Delete(::grpc::ServerContext* ctx, const DeleteRequest* req, OpStatus* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        std::string err;
        DeleteSafe(Utf8ToWide(req->path()), cfg_.trashDir, req->no_trash(), &err);
        FillStatus(resp, err);
        return grpc::Status::OK;
    }

    // v7: agent-local file tail. No driver call — pure Win32 CreateFile /
    // SetFilePointerEx / ReadFile via log_ring.hpp. Kills the "234 MB
    // kernel-log pull" pattern from the developer feedback.
    grpc::Status LogTail(::grpc::ServerContext* ctx, const LogTailRequest* req,
                         LogTailResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) return auth;
        auto r = LogRing::Tail(Utf8ToWide(req->path()),
                                req->bytes(),
                                req->from_end() || req->bytes() == 0 || true,
                                req->line_align(),
                                req->include_rotated());
        if (!r.ok) {
            FillStatus(resp, r.error);
            return grpc::Status::OK;
        }
        resp->set_data(r.data.data(), r.data.size());
        resp->set_total_size(r.total_size);
        resp->set_tail_offset(r.tail_offset);
        resp->set_truncated(r.truncated);
        resp->set_rotated_size(r.rotated_size);
        resp->set_via_snapshot(r.via_shadow);
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

    // v8: server-streaming tail -f. Same underlying share flags as LogTail;
    // rotation-aware; concurrency-capped via the FollowInstance() gate. The
    // stream terminates on client cancel, duration, max_bytes, io_error,
    // path_gone, or agent shutdown (all as terminal chunks with eof=true).
    grpc::Status LogFollow(::grpc::ServerContext* ctx, const LogFollowRequest* req,
                           ::grpc::ServerWriter<LogFollowChunk>* writer) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) return auth;

        if (!FollowInstance().TryAcquire()) {
            LogFollowChunk deny;
            deny.set_eof(true);
            deny.set_reason("cap");
            FillStatus(&deny, "follow: SUSPX_MAX_FOLLOWS cap reached");
            writer->Write(deny);
            return grpc::Status::OK;
        }
        struct GateGuard {
            ~GateGuard() { FollowInstance().Release(); }
        } guard;

        // First chunk carries ok=true so a caller can bind the stream
        // before any data arrives (matches Memory.Watch semantics).
        LogFollowChunk hello;
        FillStatus(&hello, "");
        if (!writer->Write(hello)) {
            return grpc::Status::OK;
        }

        auto emit = [&](const FollowChunkLite& c) -> bool {
            LogFollowChunk out;
            out.set_offset(c.offset);
            if (!c.data.empty()) {
                out.set_data(c.data.data(), c.data.size());
            }
            out.set_rotated(c.rotated);
            out.set_new_total_size(c.new_total_size);
            out.set_stat_only(c.stat_only);
            FillStatus(&out, "");
            return writer->Write(out);
        };
        auto cancelled = [ctx]() -> bool { return ctx->IsCancelled(); };

        std::string reason = LogRing::Follow(
            Utf8ToWide(req->path()),
            req->from_offset(),
            req->initial_tail_bytes(),
            req->poll_interval_ms(),
            req->max_chunk_bytes(),
            req->line_align(),
            req->follow_rotation(),
            req->duration_s(),
            req->max_bytes(),
            emit, cancelled);

        LogFollowChunk eof;
        eof.set_eof(true);
        if (reason.rfind("io_error", 0) == 0) {
            eof.set_reason("io_error");
            FillStatus(&eof, reason);
        } else {
            eof.set_reason(reason.empty() ? "cancelled" : reason);
            FillStatus(&eof, "");
        }
        writer->Write(eof);
        return grpc::Status::OK;
    }

private:
    static std::wstring Utf8ToWide(const std::string& s)
    {
        int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
        std::wstring w(n ? n - 1 : 0, L'\0');
        if (n) {
            MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, w.data(), n);
        }
        return w;
    }
    static std::string WideToUtf8(const std::wstring& w)
    {
        int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, nullptr, 0, nullptr, nullptr);
        std::string s(n ? n - 1 : 0, '\0');
        if (n) {
            WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, s.data(), n, nullptr, nullptr);
        }
        return s;
    }
    const AgentConfig& cfg_;
    DriverMgr& drv_;
    std::reference_wrapper<ExecMgr> execRef_;
};

// Facade helper: builds the singleton FilesSvc and registers it. Called from
// RegisterFileExecServices in services2.cpp. Kept in this TU so the class
// definition never leaks through a header (matches the original single-TU
// static-local pattern exactly).
void RegisterFilesSvcInto(grpc::ServerBuilder& builder, const AgentConfig& cfg, DriverMgr& drv,
                          ExecMgr& exec)
{
    static FilesSvc filesSvc(cfg, drv, exec);
    builder.RegisterService(&filesSvc);
}

} // namespace suspex
