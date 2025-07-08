// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#pragma once

#include "event/Loop.hxx"
#include "event/ShutdownListener.hxx"
#include "event/SignalEvent.hxx"
#include "event/FineTimerEvent.hxx"
#include "io/UniqueFileDescriptor.hxx"

#include <memory>
#include <set>
#include <string>

class UnifiedCgroupWatch;
class LuaAccounting;
class CgroupAccountingCollector;
class CgroupAccountingServer;
struct lua_State;

class Instance final {
	EventLoop event_loop;

	bool should_exit = false;

	ShutdownListener shutdown_listener;
	SignalEvent sighup_event;

	const UniqueFileDescriptor root_cgroup;

	std::unique_ptr<CgroupAccountingCollector> accounting_collector;
	std::unique_ptr<CgroupAccountingServer> accounting_server;

	std::unique_ptr<UnifiedCgroupWatch> unified_cgroup_watch;

	std::unique_ptr<LuaAccounting> lua_accounting;

	std::set<std::string> cgroup_delete_queue;
	FineTimerEvent defer_cgroup_delete;

public:
	Instance();
	~Instance() noexcept;

	EventLoop &GetEventLoop() noexcept {
		return event_loop;
	}

	void Run() noexcept {
		event_loop.Run();
	}

private:
	static int LuaAccountingListen(lua_State* L);
	static std::unique_ptr<LuaAccounting>
	LoadLuaAccounting(EventLoop &event_loop, const char *path, Instance *instance);

	void OnExit() noexcept;
	void OnReload(int) noexcept;

	void OnCgroupAdded(const char *path) noexcept;
	void OnCgroupEmpty(const char *path) noexcept;
	void OnDeferredCgroupDelete() noexcept;

	void AccountingListen(const char* socket, uint32_t interval_ms);
};
