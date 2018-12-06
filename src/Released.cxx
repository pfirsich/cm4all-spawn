/*
 * Copyright 2017-2018 Content Management AG
 * All rights reserved.
 *
 * author: Max Kellermann <mk@cm4all.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * - Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *
 * - Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the
 * distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * FOUNDATION OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "Instance.hxx"
#include "Scopes.hxx"
#include "system/Error.hxx"
#include "io/UniqueFileDescriptor.hxx"
#include "util/StringCompare.hxx"
#include "util/ScopeExit.hxx"
#include "util/PrintException.hxx"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <inttypes.h>

static const char *
GetManagedSuffix(const char *path)
{
	for (auto i = managed_scopes; *i != nullptr; ++i) {
		const char *suffix = StringAfterPrefix(path, *i);
		if (suffix != nullptr)
			return suffix;
	}

	return nullptr;
}

static UniqueFileDescriptor
OpenCgroupFile(const char *relative_path, const char *controller_name,
	       const char *filename)
{
	char path[4096];
	snprintf(path, sizeof(path), "/sys/fs/cgroup/%s%s/%s.%s",
		 controller_name, relative_path,
		 controller_name, filename);

	UniqueFileDescriptor fd;
	if (!fd.OpenReadOnly(path))
		throw FormatErrno("Failed to open %s", path);
	return fd;
}

static uint64_t
ReadCgroupNumber(const char *relative_path, const char *controller_name,
		 const char *filename)
{
	auto fd = OpenCgroupFile(relative_path, controller_name, filename);
	char data[64];
	ssize_t nbytes = fd.Read(data, sizeof(data) - 1);
	if (nbytes < 0)
		throw MakeErrno("Failed to read");

	data[nbytes] = 0;

	char *endptr;
	auto value = strtoull(data, &endptr, 10);
	if (endptr == data)
		throw std::runtime_error("Failed to parse number");

	return value;
}

static void
CollectCgroupStats(const char *relative_path, const char *suffix)
{
	// TODO: blkio
	// TODO: multicast statistics

	char buffer[4096];
	size_t position = 0;

	try {
		position += sprintf(buffer + position, " cpuacct.usage=%" PRIu64,
				    ReadCgroupNumber(relative_path, "cpuacct", "usage"));
	} catch (...) {
		PrintException(std::current_exception());
	}

	try {
		position += sprintf(buffer + position, " cpuacct.usage_user=%" PRIu64,
				    ReadCgroupNumber(relative_path, "cpuacct", "usage_user"));
	} catch (...) {
		PrintException(std::current_exception());
	}

	try {
		position += sprintf(buffer + position, " cpuacct.usage_sys=%" PRIu64,
				    ReadCgroupNumber(relative_path, "cpuacct", "usage_sys"));
	} catch (...) {
		PrintException(std::current_exception());
	}

	try {
		position += sprintf(buffer + position,
				    " memory.max_usage_in_bytes=%" PRIu64,
				    ReadCgroupNumber(relative_path, "memory",
						     "max_usage_in_bytes"));
	} catch (...) {
		PrintException(std::current_exception());
	}

	if (position > 0)
		fprintf(stderr, "%s:%.*s\n", suffix, int(position), buffer);
}

static void
DestroyCgroup(const CgroupState &state, const char *relative_path)
{
	for (const auto &mount : state.mounts) {
		char buffer[4096];
		snprintf(buffer, sizeof(buffer), "/sys/fs/cgroup/%s%s",
			 mount.c_str(), relative_path);
		if (rmdir(buffer) < 0 && errno != ENOENT)
			fprintf(stderr, "Failed to delete '%s': %s\n",
				buffer, strerror(errno));
	}
}

void
Instance::OnSystemdAgentReleased(const char *path)
{
	const char *suffix = GetManagedSuffix(path);
	if (suffix == nullptr)
		return;

	printf("Cgroup released: %s\n", path);

	CollectCgroupStats(path, suffix);
	fflush(stdout);

	// TODO: delay this call?
	DestroyCgroup(cgroup_state, path);
}
