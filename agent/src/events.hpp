#pragma once

#include <condition_variable>
#include <cstdint>
#include <deque>
#include <mutex>
#include <chrono>

namespace suspex {

// bounded FIFO used for debug events and shell console streams; keeps a
// bounded tail of everything pushed so late subscribers can replay (from_seq)
template <typename T>
class EventQueue {
public:
    explicit EventQueue(size_t cap = 4096, size_t historyCap = 1024)
        : cap_(cap), historyCap_(historyCap) {}

    void Push(T v)
    {
        {
            std::lock_guard<std::mutex> lk(m_);
            if (q_.size() >= cap_) {
                q_.pop_front(); // shed oldest under pressure
            }
            q_.push_back(v);
            history_.push_back(v);
            if (history_.size() > historyCap_) {
                history_.pop_front();
            }
        }
        cv_.notify_one();
    }

    // false on timeout
    template <typename Rep, typename Period>
    bool Pop(T* out, std::chrono::duration<Rep, Period> wait)
    {
        std::unique_lock<std::mutex> lk(m_);
        if (!cv_.wait_for(lk, wait, [&] { return !q_.empty(); })) {
            return false;
        }
        *out = std::move(q_.front());
        q_.pop_front();
        return true;
    }

    // replay: buffered history items matching pred (e.g. seq >= from_seq).
    // Live Pop() may still deliver overlapping items — dedupe by seq.
    template <typename Pred>
    void SnapshotIf(Pred pred, std::deque<T>* out)
    {
        std::lock_guard<std::mutex> lk(m_);
        for (const T& item : history_) {
            if (pred(item)) {
                out->push_back(item);
            }
        }
    }

    void Wake()
    {
        cv_.notify_all();
    }

private:
    size_t cap_;
    size_t historyCap_;
    std::deque<T> q_;
    std::deque<T> history_;
    std::mutex m_;
    std::condition_variable cv_;
};

} // namespace suspex
