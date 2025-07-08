// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#include "CgroupAccounting.hxx"
#include "lib/fmt/ToBuffer.hxx"
#include "net/LocalSocketAddress.hxx"
#include "system/Error.hxx"
#include "io/SmallTextFile.hxx"
#include "io/Open.hxx"
#include "io/UniqueFileDescriptor.hxx"
#include "util/NumberParser.hxx"
#include "util/PrintException.hxx"
#include "util/SpanCast.hxx"
#include "util/StringCompare.hxx"
#include "util/StringStrip.hxx"

#include <nlohmann/json.hpp>

#include <fcntl.h>
#include <sys/xattr.h>

using std::string_view_literals::operator""sv;

static CgroupCpuStat
ReadCgroupCpuStat(FileDescriptor cgroup_fd)
{
	CgroupCpuStat result;

	for (const std::string_view line : IterableSmallTextFile<4096>{FileAt{cgroup_fd, "cpu.stat"}}) {
		const auto [name, value_s] = Split(line, ' ');

		if (name == "usage_usec"sv) {
			if (auto value = ParseInteger<uint_least64_t>(value_s))
				result.total = std::chrono::microseconds(*value);
		} else if (name == "user_usec"sv) {
			if (auto value = ParseInteger<uint_least64_t>(value_s))
				result.user = std::chrono::microseconds(*value);
		} else if (name == "system_usec"sv) {
			if (auto value = ParseInteger<uint_least64_t>(value_s))
				result.system = std::chrono::microseconds(*value);
		}
	}

	return result;
}

CgroupResourceUsage
ReadCgroupResourceUsage(FileDescriptor cgroup_fd) noexcept
{
	// TODO: blkio

	CgroupResourceUsage result;

	try {
		result.cpu = ReadCgroupCpuStat(cgroup_fd);
	} catch (...) {
		PrintException(std::current_exception());
	}

	try {
		WithSmallTextFile<64>(FileAt{cgroup_fd, "memory.peak"}, [&result](std::string_view contents){
			if (auto value = ParseInteger<uint_least64_t>(StripRight(contents))) {
				result.memory_peak = *value;
				result.have_memory_peak = true;
			}
		});
	} catch (...) {
	}

	try {
		for (const std::string_view line : IterableSmallTextFile<4096>{FileAt{cgroup_fd, "memory.events"}}) {
			const auto [name, value_s] = Split(line, ' ');

			if (name == "high"sv) {
				if (auto value = ParseInteger<uint_least32_t>(value_s)) {
					result.memory_events_high = *value;
					result.have_memory_events_high = true;
				}
			} else if (name == "max"sv) {
				if (auto value = ParseInteger<uint_least32_t>(value_s)) {
					result.memory_events_max = *value;
					result.have_memory_events_max = true;
				}
			} else if (name == "oom"sv) {
				if (auto value = ParseInteger<uint_least32_t>(value_s)) {
					result.memory_events_oom = *value;
					result.have_memory_events_oom = true;
				}
			}
		}
	} catch (...) {
	}

	try {
		WithSmallTextFile<64>(FileAt{cgroup_fd, "pids.peak"}, [&result](std::string_view contents){
			if (auto value = ParseInteger<uint_least32_t>(StripRight(contents))) {
				result.pids_peak = *value;
				result.have_pids_peak = true;
			}
		});
	} catch (...) {
	}

	try {
		WithSmallTextFile<64>(FileAt{cgroup_fd, "pids.forks"}, [&result](std::string_view contents){
			if (auto value = ParseInteger<uint_least32_t>(StripRight(contents))) {
				result.pids_forks = *value;
				result.have_pids_forks = true;
			}
		});
	} catch (...) {
	}

	try {
		for (const std::string_view line : IterableSmallTextFile<4096>{FileAt{cgroup_fd, "pids.events"}}) {
			const auto [name, value_s] = Split(line, ' ');

			if (name == "max"sv) {
				if (auto value = ParseInteger<uint_least32_t>(value_s)) {
					result.pids_events_max = *value;
					result.have_pids_events_max = true;
				}
			}
		}
	} catch (...) {
	}

	return result;
}

CgroupAccountingCollector::CgroupAccountingCollector(
	EventLoop &_event_loop, FileDescriptor _root_cgroup, std::chrono::milliseconds interval_ms)
	: event_loop(_event_loop),
	  root_cgroup(_root_cgroup),
	  interval(interval_ms),
	  timer(event_loop, BIND_THIS_METHOD(OnTimer))
{
	timer.SetDue(std::chrono::steady_clock::now() + interval);
	timer.ScheduleCurrent();
}

void
CgroupAccountingCollector::AddListener(Listener* listener) noexcept
{
	listeners.push_front(listener);
}

void
CgroupAccountingCollector::RemoveListener(Listener* listener) noexcept
{
	listeners.remove(listener);
}

static std::string
GetXattr(FileDescriptor fd, const char *name, size_t max_size = 64)
{
	// Prepend "user." attribute namespace
	assert(strlen(name) < 64);
	char name_buffer[128];
	strcpy(stpcpy(name_buffer, "user."), name);

	std::string str(max_size, '\0');
	const auto size = fgetxattr(fd.Get(), name_buffer, str.data(), str.size());
	if (size < 0) {
		throw MakeErrno(fmt::format("fgetxattr '{}'", name).c_str());
	}
	str.resize(static_cast<size_t>(size));
	return str;
}

void
CgroupAccountingCollector::AddCgroup(const char *relative_path)
{
	fmt::print(stderr, "Add cgroup: {}\n", relative_path);

	const auto scope_path =
		StringAfterPrefix(relative_path, "/system.slice/system-cm4all.slice/");
	if (!scope_path) {
		// This should not happen, because it has already been checked in
		// Instance::OnCgroupAdded
		return;
	}
	const auto scope_end = std::string_view {scope_path}.find(".scope/");
	if (scope_end == std::string_view::npos) {
		// This should also not happend
		return;
	}
	const auto scope = std::string_view {scope_path, scope_end};

	/* We insert first, so we can exit out right away if the cgroup is already tracked,
	   without opening the directory again. */
	auto [it, inserted] = cgroups.try_emplace(relative_path);

	if (!inserted) {
		fmt::print(stderr, "Cgroup already tracked\n");
		return;
	}

	auto &cgroup = it->second;

	try {
		if (!cgroup.fd.Open(root_cgroup, relative_path + 1, O_DIRECTORY | O_RDONLY)) {
			throw MakeErrno(
				fmt::format("Could not open cgroup directory '{}'", relative_path)
					.c_str());
		}

		cgroup.pillar = GetXattr(cgroup.fd, "pillar");
		cgroup.account_id = GetXattr(cgroup.fd, "account_id");
		cgroup.global_account_id = GetXattr(cgroup.fd, "global_account_id");
		cgroup.scope = scope;
	} catch (const std::system_error &exc) {
		// Probably not a webspace cgroup, so we silently ignore it
		cgroups.erase(relative_path);
		return;
	}
}

void
CgroupAccountingCollector::RemoveCgroup(const char *relative_path, const CgroupResourceUsage &usage)
{
	auto it = cgroups.find(relative_path);
	if (it == cgroups.end()) {
		return;
	}

	fmt::print(stderr, "Remove cgroup: {}\n", relative_path);

	it->second.usage = usage;
	it->second.sample_time = std::chrono::system_clock::now();

	StartStats();
	Stats(it->second);
	EndStats();

	cgroups.erase(relative_path);
}

void 
CgroupAccountingCollector::SetInterval(std::chrono::milliseconds interval_ms)
{
	interval = interval_ms;
}

void
CgroupAccountingCollector::OnTimer() noexcept
{
	Sample();
	
	StartStats();
	for (auto& [relative_path, cgroup] : cgroups) {
		Stats(cgroup);
	}
	EndStats();

	timer.SetDue(std::chrono::steady_clock::now() + interval);
	timer.ScheduleCurrent();
}


void
CgroupAccountingCollector::Sample()
{
	for (auto& [relative_path, cgroup] : cgroups) {
		cgroup.usage = ReadCgroupResourceUsage(cgroup.fd);
		cgroup.sample_time = std::chrono::system_clock::now();
	}
}

void
CgroupAccountingCollector::StartStats()
{
	for (const auto &l : listeners) {
		l->StartStats();
	}
}

void
CgroupAccountingCollector::Stats(const CgroupStats &stats)
{
	for (const auto &l : listeners) {
		l->Stats(stats);
	}
}

void
CgroupAccountingCollector::EndStats()
{
	for (const auto &l : listeners) {
		l->EndStats();
	}
}

CgroupAccountingServer::Client::Client(EventLoop &event_loop, UniqueSocketDescriptor&& _sock)
	: sock(std::move(_sock))
	, event(event_loop, BIND_THIS_METHOD(OnRead), sock)
{
	event.ScheduleRead();
}

void
CgroupAccountingServer::Client::ParseHello(std::span<const std::byte> data)
{
	auto j = nlohmann::json::parse(data);
	for (const auto &m : j.at("metrics")) {
		if (m == "cpu.total") mask.cpu_total = true;
		else if (m == "cpu.user") mask.cpu_user = true;
		else if (m == "cpu.system") mask.cpu_system = true;
		else if (m == "memory.peak") mask.memory_peak = true;
		else if (m == "memory.events.high") mask.memory_events_high = true;
		else if (m == "memory.events.max") mask.memory_events_max = true;
		else if (m == "memory.events.oom") mask.memory_events_oom = true;
		else if (m == "pids.peak") mask.pids_peak = true;
		else if (m == "pids.forks") mask.pids_forks = true;
		else if (m == "pids.events.max") mask.pids_events_max = true;
	}
}

void
CgroupAccountingServer::Client::Close() noexcept
{
	event.Cancel();
	sock.Close();
	close = true;
}

void
CgroupAccountingServer::Client::OnRead(unsigned) noexcept
{
	if (ready) {
		return;
	}

	std::array<std::byte, 1024> buffer;
	ssize_t n = sock.Read(buffer);
	if (n <= 0) {
		Close();
		return;
	}

	try {
		ParseHello(std::span{buffer}.first(n));
		ready = true;
		event.Cancel();
	} catch (...) {
		fmt::print(stderr, "Invalid client hello\n");
		Close();
	}
}

void
CgroupAccountingServer::Client::Flush()
{
	if (serialize_buffer.empty()) {
		return;
	}
	const auto n = sock.Send(AsBytes(serialize_buffer));
	if (n < 0 && errno != EAGAIN) {
		Close();
		fmt::print(
			stderr, "Error sending accounting data to client: {}\n", strerror(errno));
		return;
	}
	serialize_buffer.clear();
}

CgroupAccountingServer::CgroupAccountingServer(EventLoop &_event_loop,
					       CgroupAccountingCollector &_collector,
					       const char* _listen_path)
	: event_loop(_event_loop),
	  collector(_collector),
	  event(event_loop, BIND_THIS_METHOD(OnAccept))
{
	collector.AddListener(this);
	Listen(_listen_path);
}

CgroupAccountingServer::~CgroupAccountingServer()
{
	collector.RemoveListener(this);
}

void
CgroupAccountingServer::Listen(const char *uds_path)
{
	if (listen_path == uds_path) {
		return;
	}

	UniqueSocketDescriptor sock;
	if (!sock.CreateNonBlock(AF_UNIX, SOCK_SEQPACKET, 0)) {
		throw MakeErrno("Failed to create socket");
	}

	LocalSocketAddress address {uds_path};
	(void)unlink(uds_path);
	if (!sock.Bind(address)) {
		throw MakeErrno("Failed to bind socket");
	}

	if (!sock.Listen(8)) {
		throw MakeErrno("Failed to listen");
	}

	event.Open(sock);
	event.ScheduleRead();

	socket.Close();
	socket = std::move(sock);

	listen_path = uds_path;
}

void
CgroupAccountingServer::OnAccept(unsigned) noexcept
{
	for (;;) {
		auto sock = socket.AcceptNonBlock();
		if (!sock.IsDefined()) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				break;
			}
			fmt::print(stderr, "Error accepting accounting connection: {}\n",
				   strerror(errno));
			break;
		}
		fmt::print(stderr, "CgroupAccountingServer: accepted connection\n");
		clients.emplace_front(event_loop, std::move(sock));
	}
}

void
CgroupAccountingServer::AppendStats(
	std::string &buffer, const CgroupStats &stats, const MetricMask &mask)
{
	const auto timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
		stats.sample_time.time_since_epoch()).count();
	nlohmann::json j {
		{"pillar", stats.pillar},
		{"account_id", stats.account_id},
		{"scope", stats.scope},
		{"global_account_id", stats.global_account_id},
		{"timestamp_ms", timestamp},
	};
	if (mask.cpu_total) j["cpu.total"] = stats.usage.cpu.total.count();
	if (mask.cpu_user) j["cpu.user"] = stats.usage.cpu.user.count();
	if (mask.cpu_system) j["cpu.system"] = stats.usage.cpu.system.count();
	if (mask.memory_peak) j["memory.peak"] = stats.usage.memory_peak;
	if (mask.memory_events_high) j["memory.events.high"] = stats.usage.memory_events_high;
	if (mask.memory_events_max) j["memory.events.max"] = stats.usage.memory_events_max;
	if (mask.memory_events_oom) j["memory.events.oom"] = stats.usage.memory_events_oom;
	if (mask.pids_peak) j["pids.peak"] = stats.usage.pids_peak;
	if (mask.pids_forks) j["pids.forks"] = stats.usage.pids_forks;
	if (mask.pids_events_max) j["pids.events.max"] = stats.usage.pids_events_max;
	buffer.append(j.dump());
	buffer.push_back('\n');
}

void
CgroupAccountingServer::StartStats()
{
	for (auto client = clients.begin(); client != clients.end();) {
		if (client->close) {
			client = clients.erase(client);
			continue;
		}
		++client;
	}
}

void
CgroupAccountingServer::Stats(const CgroupStats& stats)
{
	for (auto &client : clients) {
		if (!client.ready || client.close) {
			continue;
		}

		AppendStats(client.serialize_buffer, stats, client.mask);

		if (client.serialize_buffer.size() >= 64 * 1024) {
			client.Flush();
		}
	}
}

void
CgroupAccountingServer::EndStats()
{
	for (auto client = clients.begin(); client != clients.end();) {
		if (client->close) {
			client = clients.erase(client);
			continue;
		}

		if (!client->ready) {
			++client;
			continue;
		}

		client->Flush();

		++client;
	}
}