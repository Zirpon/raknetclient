#define LUA_LIB
extern "C" {
#include <lua.h>
#include <lauxlib.h>
}

#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <assert.h>

#ifndef skynet_malloc
#define skynet_malloc malloc
#endif

extern "C" {
	extern void connection_close(uint32_t handle, uint32_t fd);
	extern void connection_open(uint32_t handle, uint32_t fd);
	extern void connection_read(uint32_t handle, uint32_t fd, uint32_t pid, const uint8_t* msg, int sz);

	extern int skynet_rak_push(uint32_t handle, const char *message, int sz);
	extern void * skynet_malloc(size_t sz);

	LUAMOD_API int luaopen_rakclient_core(lua_State *L);
}

extern void init(uint16_t port, const char* conPwd);
extern void closefd(uint32_t fd);
extern void rak_async_send();
extern void rak_async_revc();
extern void rak_send(uint32_t index, uint32_t handle, uint16_t pid, const void* msg, uint32_t len);
extern void rak_ping(uint32_t index);

extern void NewClient(uint32_t handle, const char* ip, uint16_t port, const char* conPwd, uint32_t remoteHandler);
extern void CloseClient(uint32_t handle);

void connection_close(uint32_t handle, uint32_t fd)
{
	char* buf = (char*)skynet_malloc(5);
	*buf = 2;
	memcpy(buf+1, &fd, 4);
	skynet_rak_push(handle, buf, 5);
}
void connection_open(uint32_t handle, uint32_t fd)
{
	char* buf = (char*)skynet_malloc(5);
	*buf = 1;
	memcpy(buf + 1, &fd, 4);
	skynet_rak_push(handle, buf, 5);
}
void connection_read(uint32_t handle, uint32_t fd, uint32_t pid, const uint8_t* msg, int sz)
{
	int totalsz = sz + 9;
	char* buf = (char*)skynet_malloc(totalsz);
	*buf = 3;
	memcpy(buf + 1, &fd, 4);
	memcpy(buf + 5, &pid, 4);
	memcpy(buf + 9, msg, sz);
	skynet_rak_push(handle, buf, totalsz);
}

static int
linit(lua_State *L) {
	int port = lua_tointeger(L, 1);
	size_t sz = 0;
	const char* pwd = luaL_checklstring(L, 2, &sz);
	char buf[128] = { 0 };
	memcpy(buf, pwd, sz);
	buf[sz] = '\0';

	init(port, buf);

	return 0;
}

static int
lnewclient(lua_State *L)
{
	size_t sz = 0;
	char ipbuf[128] = { 0 };
	char pwdbuf[128] = { 0 };

	int handle = lua_tointeger(L, 1);
	const char* ip = luaL_checklstring(L, 2, &sz);
	memcpy(ipbuf, ip, sz);
	ipbuf[sz] = '\0';
	
	int port = lua_tointeger(L, 3);
	const char* pwd = luaL_checklstring(L, 4, &sz);
	memcpy(pwdbuf, pwd, sz);
	pwdbuf[sz] = '\0';
	int remoteHandler = lua_tointeger(L, 5);

	NewClient(handle, ipbuf, port, pwdbuf, remoteHandler);

	return 0;
}

static int
lcloseclient(lua_State *L)
{
	int handle = lua_tointeger(L, 1);
	CloseClient(handle);

	return 0;
}

static int
lwrite(lua_State *L) {
	int fd = lua_tointeger(L, 1);
	int pid = lua_tointeger(L, 2);
	const char* msg = (const char*)lua_touserdata(L, 3);
	int sz = lua_tointeger(L, 4);
	int index = lua_tointeger(L, 5);

	rak_send(index, fd, pid, msg, sz);

	return 0;
}

static int
lping(lua_State *L) {
	int index = lua_tointeger(L, 1);
	rak_ping(index);
	return 0;
}

static int
lclosefd(lua_State *L) {
	int fd = lua_tointeger(L, 1);
	closefd(fd);

	return 0;
}

#define  RAK_DATA_OPEN  1
#define  RAK_DATA_CLOSE 2
#define  RAK_DATA_MSG   3
static int
lunpack(lua_State *L) {
	const char* msg = (const char*)lua_touserdata(L, 1);
	int sz = lua_tointeger(L, 2);

	if (sz <= 0 )
	{
		return luaL_error(L, "rak lunpack error=>[sz is <0]");
	}

	int type = msg[0];
	lua_pushinteger(L, type);
	switch (type)
	{
	case RAK_DATA_OPEN:
	case RAK_DATA_CLOSE:
	{
		uint32_t fd = 0;
		memcpy(&fd, msg + 1, 4);

		lua_pushinteger(L, fd);
		return 2;
	}
	case RAK_DATA_MSG:
	{
		uint32_t fd = 0;
		memcpy(&fd, msg + 1, 4);
		int pid = 0;
		memcpy(&pid, msg + 5, 4);

		lua_pushinteger(L, fd);
		lua_pushinteger(L, pid);
		lua_pushlightuserdata(L, (void*)(msg + 9));
		lua_pushinteger(L, sz - 9);

		return 5;
	}
		break;
	default:
		return luaL_error(L, "rak lunpack unknow type=>[%d]", type);
	}

	return 0;
}

LUAMOD_API int
luaopen_rakclient_core(lua_State *L) {
	luaL_Reg l[] = {
		{ "init", linit },
		{ "write", lwrite },
		{ "closefd", lclosefd },
		{ "unpack", lunpack },
		{ "newclient", lnewclient },
		{ "closeclient", lcloseclient },
		{ "ping", lping },
		{ NULL, NULL },

	};
	luaL_newlib(L, l);

	return 1;
}