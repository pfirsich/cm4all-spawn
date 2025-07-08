// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#pragma once

#include "event/Chrono.hxx"
#include "event/FineTimerEvent.hxx"
#include "event/SocketEvent.hxx"
#include "net/UniqueSocketDescriptor.hxx"
#include "util/BindMethod.hxx"

#include <chrono>
#include <cstdint>
#include <forward_list>
#include <list>
#include <unordered_map>

class FileDescriptor;
class EventLoop;

struct CgroupCpuStat {
	using Duration = std::chrono::duration<double>;

	Duration total{-1}, user{-1}, system{-1};
};

struct CgroupResourceUsage {
	CgroupCpuStat cpu;

	uint_least64_t memory_peak;

	uint_least32_t memory_events_high, memory_events_max, memory_events_oom;

	uint_least32_t pids_peak, pids_forks, pids_events_max;

	bool have_memory_peak = false;

	bool have_memory_events_high = false, have_memory_events_max = false;
	bool have_memory_events_oom = false;

	bool have_pids_peak = false, have_pids_forks = false, have_pids_events_max = false;
};

struct CgroupStats {
	UniqueFileDescriptor fd;
	std::string pillar;
	std::string account_id;
	std::string global_account_id;
	std::string scope;
	CgroupResourceUsage usage;
	std::chrono::time_point<std::chrono::system_clock> sample_time;

	CgroupStats() = default;
	CgroupStats(const CgroupStats&) = delete;
	CgroupStats& operator=(const CgroupStats&) = delete;
};

[[gnu::pure]]
CgroupResourceUsage
ReadCgroupResourceUsage(FileDescriptor cgroup_fd) noexcept;

class CgroupAccountingCollector {
public:
	struct Listener {
		virtual void StartStats() = 0;
		virtual void Stats(const CgroupStats&) = 0;
		virtual void EndStats() = 0;
	};

private:
	using ListenerCallback = BoundMethod<void(const CgroupStats &)>;

	EventLoop& event_loop;
	FileDescriptor root_cgroup;
	std::forward_list<Listener*> listeners;
	// unordered_map over map, because iteration is the most common operation
	std::unordered_map<std::string, CgroupStats> cgroups;
	std::chrono::milliseconds interval;
	FineTimerEvent timer;

public:
	explicit CgroupAccountingCollector(EventLoop &event_loop, FileDescriptor root_cgroup,
		std::chrono::milliseconds interval_ms);

	void AddListener(Listener* listener) noexcept;
	void RemoveListener(Listener* listener) noexcept;

	void AddCgroup(const char *relative_path);
	void RemoveCgroup(const char *relative_path, const CgroupResourceUsage &usage);

	void SetInterval(std::chrono::milliseconds interval_ms);

private:
	void OnTimer() noexcept;
	void Sample();
	void StartStats();
	void Stats(const CgroupStats&);
	void EndStats();
};

class CgroupAccountingServer : public CgroupAccountingCollector::Listener {
	struct MetricMask {
		bool cpu_total = false;
		bool cpu_user = false;
		bool cpu_system = false;
		bool memory_peak = false;
		bool memory_events_high = false;
		bool memory_events_max = false;
		bool memory_events_oom = false;
		bool pids_peak = false;
		bool pids_forks = false;
		bool pids_events_max = false;
	};

	struct Client {
		std::string serialize_buffer;
		UniqueSocketDescriptor sock;
		SocketEvent event;
		MetricMask mask;
		bool ready = false;
		bool close = false;

		Client(EventLoop &event_loop, UniqueSocketDescriptor&& sock);
		void ParseHello(std::span<const std::byte> data);
		void Close() noexcept;
		void OnRead(unsigned) noexcept;
		void Flush();
	};

	EventLoop& event_loop;
	CgroupAccountingCollector &collector;
	UniqueSocketDescriptor socket;
	SocketEvent event;
	std::list<Client> clients;
	std::string listen_path;

public:
	CgroupAccountingServer(EventLoop &event_loop, CgroupAccountingCollector &collector, 
		const char* listen_path);
	~CgroupAccountingServer();
	void Listen(const char *uds_path);

private:
	static void AppendStats(std::string &buffer, const CgroupStats &stats, const MetricMask& mask);

	void OnAccept(unsigned) noexcept;
	void OnRead(unsigned) noexcept;

	void StartStats() override;
	void Stats(const CgroupStats& stats) override;
	void EndStats() override;
};