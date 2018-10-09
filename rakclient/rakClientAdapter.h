#pragma once

#include <string>
#include <sstream>  
#include <iostream>
#include "raknet/RakSleep.h"
#include "raknet/RakPeerInterface.h"
#include "raknet/RakNetTypes.h"
#include "raknet/MessageIdentifiers.h" // RakNet�Զ�����Ϣö�ٶ��崦 
#include "raknet/BitStream.h"  // RakNet��Ϣ����Bit������
#include "pthread.h"
#include <unordered_map>
#include <list>
#include <stack>

#include "spinlock.h"

using namespace RakNet;

extern "C" {
	struct skynet_context;
	extern void skynet_error(struct skynet_context * context, const char *msg, ...);
}

typedef struct _t_msg_buffer
{
	uint32_t handle;
	RakNet::BitStream pkg;
} CMsgBuffer;

typedef struct _t_udp_endpoint {
	SystemAddress m_GUID;
	uint32_t m_Opraue;
	uint32_t m_SerialID;
	uint8_t* m_RevBuffer;
	uint32_t m_RevSerial;
	uint8_t m_RevLsPack;
	uint8_t m_RevTotalPack;
	uint32_t m_RevBuffPos;
} CUDPEndPoint;

class stUDPAdapter 
{
	RakNet::RakPeerInterface* gServerInst;
	uint16_t m_Port;
	char* pKey;
public:
	uint32_t m_handle;
	uint32_t m_remoteHandler;
	uint64_t m_counter;

	std::unordered_map<uint32_t, CUDPEndPoint> m_MapRemote;
	pthread_rwlock_t  m_RWLock;

	std::list<CMsgBuffer*>* m_Reader;
	std::list<CMsgBuffer*>* m_Writer;
	struct HALSpinLock m_Lock;

	std::stack<CMsgBuffer*> m_BufferPool;
//	pthread_mutex_t m_PoolLock;
	struct HALSpinLock m_splock;
public:
	stUDPAdapter();
	virtual ~stUDPAdapter();

	int start(uint16_t port, std::string conPwd);

	int DispatchMsg(void*param = NULL);

	int Send(uint32_t handle, uint16_t pid, const void* msg, uint32_t len);

	int shutdown(uint32_t guid);

	void Ping();

	void RakAsyncSend();

	int clientMode(uint32_t handle, std::string ip, uint16_t port, std::string conPwd, uint32_t remoteHandler);
private:
	inline void writeMsg(CMsgBuffer* newbuffer)
	{
		sp_lock(&m_Lock);
		this->m_Writer->push_back(newbuffer);
		sp_unlock(&m_Lock);		
	}
	inline void swap()
	{
		sp_lock(&m_Lock);
		//skynet_error(NULL,"rakclientadapter:swap:locked[%x]", (unsigned int)pthread_self());
		if (this->m_Writer->empty())
		{
			//skynet_error(NULL,"rakclientadapter:swap:locked:writer empty[%x]", (unsigned int)pthread_self());
			sp_unlock(&m_Lock);
			return;
		}
		std::list<CMsgBuffer*>* tmp = NULL;
		tmp = this->m_Reader;
		this->m_Reader = this->m_Writer;
		this->m_Writer = tmp;
		sp_unlock(&m_Lock);
	}
	inline CMsgBuffer* getBuffer()
	{
//		pthread_mutex_lock(&m_PoolLock);
		sp_lock(&m_splock);
		if (this->m_BufferPool.empty())
		{
//			pthread_mutex_unlock(&m_PoolLock);
			sp_unlock(&m_splock);
			return new CMsgBuffer();
		}
		else
		{
			CMsgBuffer* buffer = this->m_BufferPool.top();
			this->m_BufferPool.pop();
//			pthread_mutex_unlock(&m_PoolLock);
			sp_unlock(&m_splock);
			return buffer;
		}
	}
	inline void PushBuffer(CMsgBuffer* buffer)
	{
//		pthread_mutex_lock(&m_PoolLock);
		sp_lock(&m_splock);
		if(this->m_BufferPool.size() > 256)
		{
			sp_unlock(&m_splock);
			delete buffer;
			return;
		}
		this->m_BufferPool.push(buffer);
		sp_unlock(&m_splock);
//		pthread_mutex_unlock(&m_PoolLock);
	}
};

extern bool g_Init;
extern bool g_RakRunable;
extern stUDPAdapter* g_RakAdapter;
extern void init(uint16_t port, const char* conPwd);
extern void closefd(uint32_t fd);
extern void* rak_async_send(void* param);
extern void* rak_async_revc(void* param);
extern void rak_send(uint32_t index, uint32_t handle, uint16_t pid, const void* msg, uint32_t len);
extern void rak_ping(uint32_t index);
