// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#include "Instance.hxx"
#include "CgroupAccounting.hxx"
#include "Scopes.hxx"
#include "UnifiedWatch.hxx"
#include "LAccounting.hxx"
#include "LInit.hxx"
#include "lua/PushCClosure.hxx"
#include "lua/RunFile.hxx"
#include "lib/fmt/RuntimeError.hxx"
#include "io/Open.hxx"
#include "util/PrintException.hxx"
#include "util/ScopeExit.hxx"

extern "C" {
#include <lauxlib.h>
}

#include <signal.h>

static auto
CreateUnifiedCgroupWatch(EventLoop &event_loop,
			 const FileDescriptor root_cgroup,
			 auto added_callback, auto empty_callback)
{
	assert(root_cgroup.IsDefined());

	auto watch = std::make_unique<UnifiedCgroupWatch>(event_loop,
							  root_cgroup,
							  added_callback,
							  empty_callback);
	for (auto i = managed_scopes; *i != nullptr; ++i) {
		const char *relative_path = *i;
		if (*relative_path == '/')
			++relative_path;

		watch->AddCgroup(relative_path);
	}

	return watch;
}

static Lua::ValuePtr
GetGlobalFunction(lua_State *L, const char *name)
{
	lua_getglobal(L, name);
	AtScopeExit(L) { lua_pop(L, 1); };

	if (lua_isnil(L, -1))
		throw FmtRuntimeError("Function '{}' not found", name);

	if (!lua_isfunction(L, -1))
		throw FmtRuntimeError("'{}' is not a function", name);

	return std::make_shared<Lua::Value>(L, Lua::RelativeStackIndex{-1});
}

int
Instance::LuaAccountingListen(lua_State *L)
{
	auto *inst = static_cast<Instance *>(lua_touserdata(L, lua_upvalueindex(1)));
	if (!inst) {
		return luaL_error(L, "Missing userdata upvalue");
	}

	const auto socket = luaL_checklstring(L, 1, nullptr);
	const auto interval = luaL_checkinteger(L, 2);

	inst->AccountingListen(socket, interval);

	return 0;
}

std::unique_ptr<LuaAccounting>
Instance::LoadLuaAccounting(EventLoop &event_loop, const char *path, Instance *instance)
{
	auto state = LuaInit(event_loop);

	Lua::SetGlobal(state.get(), "accounting_listen",
		Lua::CClosure<Lua::LightUserData>(
			Instance::LuaAccountingListen, Lua::LightUserData(instance)));

	Lua::RunFile(state.get(), path);

	auto handler = GetGlobalFunction(state.get(), "cgroup_released");

	return std::make_unique<LuaAccounting>(std::move(state), std::move(handler));
}

Instance::Instance()
	: shutdown_listener(event_loop, BIND_THIS_METHOD(OnExit)),
	  sighup_event(event_loop, SIGHUP, BIND_THIS_METHOD(OnReload)),
	  root_cgroup(OpenPath("/sys/fs/cgroup")),
	  unified_cgroup_watch(CreateUnifiedCgroupWatch(event_loop, root_cgroup,
		  BIND_THIS_METHOD(OnCgroupAdded), BIND_THIS_METHOD(OnCgroupEmpty))),
	  lua_accounting(LoadLuaAccounting(event_loop, "/etc/cm4all/spawn/reaper.lua", this)),
	  defer_cgroup_delete(event_loop, BIND_THIS_METHOD(OnDeferredCgroupDelete))
{
	shutdown_listener.Enable();
	sighup_event.Enable();
}

Instance::~Instance() noexcept = default;

void
Instance::OnExit() noexcept
{
	if (should_exit)
		return;

	should_exit = true;

	shutdown_listener.Disable();
	sighup_event.Disable();

	lua_accounting.reset();

	unified_cgroup_watch.reset();

	accounting_server.reset();
	accounting_collector.reset();
}

void
Instance::OnReload(int) noexcept
{
	if (lua_accounting)
		lua_accounting->Reload();
}

void
Instance::AccountingListen(const char* socket, uint32_t interval_ms)
{
	auto interval = std::chrono::milliseconds(interval_ms);
	if (!accounting_collector) {
		accounting_collector = std::make_unique<CgroupAccountingCollector>(event_loop, root_cgroup, interval);
	} else {
		accounting_collector->SetInterval(interval);
	}

	if (!accounting_server) {
		accounting_server = std::make_unique<CgroupAccountingServer>(event_loop, *accounting_collector, socket);
	} else {
		accounting_server->Listen(socket);
	}
}
