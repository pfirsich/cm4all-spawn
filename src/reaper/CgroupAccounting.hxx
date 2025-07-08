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
#include <map>

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
	std::string_view path;
	std::chrono::time_point<std::chrono::system_clock> timestamp;
	std::string_view pillar;
	std::string_view account_id;
	std::string_view global_account_id;
	CgroupResourceUsage usage;
};

[[gnu::pure]]
CgroupResourceUsage
ReadCgroupResourceUsage(FileDescriptor cgroup_fd) noexcept;

class CgroupAccountingCollector {
	using ListenerCallback = BoundMethod<void(const CgroupStats &)>;

	struct Cgroup {
		CgroupAccountingCollector* collector;
		std::string relative_path;
		UniqueFileDescriptor fd;
		std::string pillar;
		std::string account_id;
		std::string global_account_id;
		FineTimerEvent timer;

		Cgroup(CgroupAccountingCollector* collector, std::string relative_path);
		Cgroup(const Cgroup&) = delete;
		Cgroup(Cgroup&&) = delete;
		void Schedule();
		void OnTimer() noexcept;
	};

	EventLoop& event_loop;
	FileDescriptor root_cgroup;
	std::forward_list<ListenerCallback> listeners;
	std::map<std::string, Cgroup> cgroups;
	std::chrono::milliseconds interval;

public:
	explicit CgroupAccountingCollector(EventLoop &event_loop, FileDescriptor root_cgroup,
		std::chrono::milliseconds interval_ms);

	void AddListener(ListenerCallback cb) noexcept;
	void RemoveListener(ListenerCallback cb) noexcept;

	void AddCgroup(const char *relative_path);
	void RemoveCgroup(const char *relative_path, const CgroupResourceUsage &usage);

	void SetInterval(std::chrono::milliseconds interval_ms);

private:
	void PushStats(const Cgroup &cgroup);
	void PushStats(const Cgroup &cgroup, const CgroupResourceUsage &usage);
};

class CgroupAccountingServer {
	struct MetricMask {
		bool memory_peak = false;
		bool pids_peak = false;
	};

	struct Client {
		UniqueSocketDescriptor sock;
		SocketEvent event;
		MetricMask mask;
		bool ready = false;
		bool close = false;

		Client(EventLoop &event_loop, UniqueSocketDescriptor&& sock);
		void ParseHello(std::span<const std::byte> data);
		void Close() noexcept;
		void OnRead(unsigned) noexcept;
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
	void OnAccept(unsigned) noexcept;
	void OnRead(unsigned) noexcept;
	void OnStats(const CgroupStats &stats);
};