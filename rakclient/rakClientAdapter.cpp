#include "rakClientAdapter.h"
#include "raknet/SecureHandshake.h"
#include "raknet/GetTime.h"
#include "zlib.h"
#define MAX_FRAME_SZIE 500
#define PACKAGE_PERSZ 500
#define STATIC_CACHE_SIZE 10240

extern "C" {
	struct skynet_context;
	extern void skynet_error(struct skynet_context * context, const char *msg, ...);
	extern struct skynet_context * skynet_handle_grab(uint32_t handle);

	extern void connection_close(uint32_t handle, uint32_t fd);
	extern void connection_open(uint32_t handle, uint32_t fd);
	extern void connection_read(uint32_t handle, uint32_t fd,uint32_t pid,const uint8_t* msg,int sz);
}

stUDPAdapter::stUDPAdapter()
{
	this->m_Writer = new std::list<CMsgBuffer*>();
	this->m_Reader = new std::list<CMsgBuffer*>();
	m_handle = 0;
	m_remoteHandler = 0;
	m_counter = 0;
	// pthread_mutex_init(&m_Lock, NULL);
	pthread_rwlock_init(&m_RWLock, NULL);
	// pthread_mutex_init(&m_PoolLock, NULL);
	init_sp_lock(&m_splock);
	init_sp_lock(&m_Lock);
}
stUDPAdapter::~stUDPAdapter()
{
	// pthread_mutex_destroy(&m_Lock);
	pthread_rwlock_destroy(&m_RWLock);
	// pthread_mutex_destroy(&m_PoolLock);
	this->gServerInst->Shutdown(300);
	RakNet::RakPeerInterface::DestroyInstance(this->gServerInst);

}

inline char GetPacketIdentifier(RakNet::Packet* p)
{
	if (p == NULL || p->length == 0)
	{
		return 0xFF;
	}
	if ((uint8_t)p->data[0] == ID_TIMESTAMP)
	{
		RakAssert(p->length > sizeof(RakNet::MessageID) + sizeof(RakNet::Time));
		return (uint8_t)p->data[sizeof(RakNet::MessageID) + sizeof(RakNet::Time)];
	}
	else
	{
		return (uint8_t)p->data[0];
	}
}

#define MAX_UDP_CLIENT 5000
//#define USE_SECURITY 1
#define USER_DATA (ID_USER_PACKET_ENUM +1)
#define USER_PING (ID_USER_PACKET_ENUM +2)
#define HOST_PONG (ID_USER_PACKET_ENUM +3)
int stUDPAdapter::start(uint16_t port, std::string conPwd)
{
	this->gServerInst = RakNet::RakPeerInterface::GetInstance();
	this->m_Port = port;
	if (conPwd == "")
	{
		skynet_error(NULL, "connecte password is not seted");
	}
	this->gServerInst->SetIncomingPassword(conPwd.c_str(), conPwd.length());

	#ifdef USE_SECURITY
		cat::EasyHandshake han;
		char pkey[cat::EasyHandshake::PUBLIC_KEY_BYTES] = { 0 };
		char prKey[cat::EasyHandshake::PRIVATE_KEY_BYTES] = { 0 };
		han.GenerateServerKey(pkey, prKey);
		this->gServerInst->InitializeSecurity(pkey, prKey, false);
		this->pKey = (char*)malloc(cat::EasyHandshake::PUBLIC_KEY_BYTES);
		memcpy(this->pKey, pkey, cat::EasyHandshake::PUBLIC_KEY_BYTES);
	#endif

	RakNet::SocketDescriptor skDesptor[1];
	skDesptor[0].port = this->m_Port;
	skDesptor[0].socketFamily = AF_INET;
	skDesptor[1].port = this->m_Port;
	skDesptor[1].socketFamily = AF_INET6;
	//   RakNet::SocketDescriptor skDesptor(this->m_Port,0);
	bool ret = this->gServerInst->Startup(MAX_UDP_CLIENT, skDesptor, 1);
	this->gServerInst->SetMaximumIncomingConnections(MAX_UDP_CLIENT);
	if (!ret)
	{
		ret = this->gServerInst->Startup(MAX_UDP_CLIENT, skDesptor, 1);
		if (!ret)
		{
			skynet_error(NULL, "RakNet start fail");
			return -1;
		}
	}

	//   this->gServerInst->SetOccasionalPing(true);
	DataStructures::List<RakNet::RakNetSocket2*> sks;
	this->gServerInst->GetSockets(sks);
	for (uint32_t i = 0; i < sks.Size(); ++i)
	{
		skynet_error(NULL, "Socket Start->[%d],[%s]", i + 1, sks[i]->GetBoundAddress().ToString(true));
	}

	for (uint32_t i = 0; i < this->gServerInst->GetNumberOfAddresses(); ++i)
	{
		RakNet::SystemAddress sa = this->gServerInst->GetInternalID(RakNet::UNASSIGNED_SYSTEM_ADDRESS);
		skynet_error(NULL, "server udp addresses->[%d],[%s],[LAN=%s]", i + 1, sa.ToString(true), sa.IsLANAddress());
	}

	return 0;
}

int stUDPAdapter::clientMode(uint32_t handle, std::string ip, uint16_t port, std::string conPwd, uint32_t remoteHandler)
{
    // new 一个UDP通讯客户端实例
    this->gServerInst = RakNet::RakPeerInterface::GetInstance();
    this->gServerInst->AllowConnectionResponseIPMigration(false);
	m_handle = handle;
	m_remoteHandler = remoteHandler;
	skynet_error(NULL, "stUDPAdapter::clientMode:[handle=%u][ip=%s][port=%u][pwd=%s][remoteHandler=%u]", handle, ip.c_str(), port, conPwd.c_str(), remoteHandler);

	// 设置客户端连接端口
    RakNet::SocketDescriptor socketDescriptor;
	socketDescriptor.socketFamily = AF_INET;

	this->gServerInst->Startup(8, &socketDescriptor, 1);
	//this->gServerInst->SetOccasionalPing(true);
	RakNet::ConnectionAttemptResult car = this->gServerInst->Connect(ip.c_str(), port, conPwd.c_str(), conPwd.length());

    RakAssert(car == RakNet::CONNECTION_ATTEMPT_STARTED);
	
	return 0;
}

int stUDPAdapter::DispatchMsg(void*param)
{
	try
	{
		RakNet::Packet* Pak;
		for (Pak = this->gServerInst->Receive(); Pak; this->gServerInst->DeallocatePacket(Pak), Pak = this->gServerInst->Receive())
		{
			uint8_t pid = GetPacketIdentifier(Pak);
			// skynet_error(NULL, "stUDPAdapter::DispatchMsg:[pid=%u][addr=%s][guid=%u][m_handle=%u]\
			// [m_remoteHandler=%u][pakLen=%u][PakBit=%u][deleteData=%d][wasGenLocal=%d]",
			//	pid, Pak->systemAddress.ToString(true), RakNetGUID::ToUint32(Pak->guid), 
			//	m_handle, m_remoteHandler, Pak->length, Pak->bitSize, Pak->deleteData, Pak->wasGeneratedLocally);
			switch (pid)
			{
			case ID_DISCONNECTION_NOTIFICATION:
			case ID_CONNECTION_LOST:
			case ID_REMOTE_DISCONNECTION_NOTIFICATION:
			case ID_REMOTE_CONNECTION_LOST:
			{
				skynet_error(NULL, "Connection close [%s][guid=%u]", Pak->systemAddress.ToString(true),RakNetGUID::ToUint32(Pak->guid));
				uint32_t guid = RakNetGUID::ToUint32(Pak->guid);

				pthread_rwlock_wrlock(&m_RWLock);
				auto ep = this->m_MapRemote.find(guid);
				if (ep == this->m_MapRemote.end())
				{
					break;
				}
				if(ep->second.m_RevBuffer != NULL)
				{
					free(ep->second.m_RevBuffer);
					ep->second.m_RevBuffer = NULL;
				}

				connection_close(ep->second.m_Opraue, guid);

				this->m_MapRemote.erase(guid);
				pthread_rwlock_unlock(&m_RWLock);
			}
			break;
			
			case ID_CONNECTION_REQUEST_ACCEPTED:
			{
				// printf("Our connection request has been accepted.\n");
				skynet_error(NULL, "Our connection request has been accepted.->[%s][guid=%u][clienthandle=%u]", 
					Pak->systemAddress.ToString(true), RakNetGUID::ToUint32(Pak->guid), m_handle);

				uint32_t guid = RakNetGUID::ToUint32(Pak->guid);
				CUDPEndPoint ep;
				ep.m_Opraue = m_handle;
				ep.m_GUID = Pak->systemAddress;
				ep.m_SerialID = 0;
				ep.m_RevBuffer = NULL;
				ep.m_RevSerial = 0;
				ep.m_RevLsPack = 0;
				ep.m_RevBuffPos = 0;
				ep.m_RevTotalPack = 0;
				// skynet_error(NULL, "write lock");
				pthread_rwlock_wrlock(&m_RWLock);
				// skynet_error(NULL, "mapremote insert");
				this->m_MapRemote.insert(std::pair<uint32_t, CUDPEndPoint>(guid, ep));
				pthread_rwlock_unlock(&m_RWLock);
				// skynet_error(NULL, "write unlock");
				connection_open(m_handle, guid);
				// skynet_error(NULL, "connection open skynet msg queen rak push");
				//Ping();
			}
			break;

			case ID_NEW_INCOMING_CONNECTION:
			{
				skynet_error(NULL, "new client has connection->[%s][guid=%u]", Pak->systemAddress.ToString(true), RakNetGUID::ToUint32(Pak->guid));
				uint32_t guid = RakNetGUID::ToUint32(Pak->guid);

				CUDPEndPoint ep;
				ep.m_Opraue = 0;
				ep.m_GUID = Pak->systemAddress;
				ep.m_SerialID = 0;
				ep.m_RevBuffer = NULL;
				ep.m_RevSerial = 0;
				ep.m_RevLsPack = 0;
				ep.m_RevBuffPos = 0;
				ep.m_RevTotalPack = 0;
				pthread_rwlock_wrlock(&m_RWLock);
				this->m_MapRemote.insert(std::pair<uint32_t, CUDPEndPoint>(guid, ep));
				pthread_rwlock_unlock(&m_RWLock);
				//                this->gServerInst->SetTimeoutTime(5000, Pak->systemAddress);
			}
			break;

			case HOST_PONG:
			{
				skynet_error(NULL, "udpadapter:dispatchmsg:HOST_PONG->[%s][guid=%u]", Pak->systemAddress.ToString(true), RakNetGUID::ToUint32(Pak->guid));

				RakNet::BitStream inBitStream( (unsigned char *) Pak->data, Pak->length, false );
				inBitStream.IgnoreBits(8);
				RakNet::Time sendPingTime;
				RakNet::Time sendPongTime;
				RakNet::Time curTime;
				curTime = RakNet::GetTime();
				inBitStream.Read(sendPingTime);
				inBitStream.Read(sendPongTime);

				skynet_error(NULL, "udpadapter:dispatchmsg:HOST_PONG:pingtime=%llu, pongtime=%llu, curTime=%llu, c2s_cost=, s2c_cost=, totalcost=%llu",
				sendPingTime,sendPongTime,curTime, curTime-sendPingTime);
			}
			break;

			case ID_NO_FREE_INCOMING_CONNECTIONS:
				skynet_error(NULL, "The server has full[%d]", MAX_UDP_CLIENT);
			break;

			case USER_DATA:
			{
				//                RakNet::RakString ndata;
				//                RakNet::BitStream sData(Pak->data,Pak->length,false);
				//                sData.IgnoreBits(sizeof(RakNet::MessageID));
				//                sData.Read(ndata);

				uint32_t guid = RakNetGUID::ToUint32(Pak->guid);
				uint16_t pos = sizeof(uint16_t) + sizeof(uint32_t);

				if(Pak->length < 4 + pos )
				{
					break;
				}

				pthread_rwlock_rdlock(&m_RWLock);
				auto ep = this->m_MapRemote.find(guid);
				if (ep == this->m_MapRemote.end())
				{
					break;
				}

				RakNet::BitStream sData(Pak->data, Pak->length, false);
				sData.IgnoreBits(2 * 8);

				//skynet_error(NULL, "udpadapter:dispatchmsg:userdata: [guid=%u][m_Opraue=%d][m_SerialID=%d][data[1]=%x][pakLen=%d][addr=%s]", 
				//	guid, ep->second.m_Opraue, ep->second.m_SerialID, Pak->data[1], Pak->length,Pak->systemAddress.ToString(true));

				if (Pak->data[1] == 0x01)//×¢²áÍæ¼Òµ½actor
				{
					if (ep->second.m_Opraue == 0)
					{
						//                        sData.IgnoreBits(pos*8);
						uint16_t pid = 0;
						uint32_t serialid = 0;
						uint16_t pading = 0;
						sData.Read(pid);
						sData.Read(serialid);
						sData.Read(pading);

						uint32_t handle = 0;
						//                    uint64_t player = 0;
						sData.Read(handle);

						skynet_error(NULL, "udpadapter:dispatchmsg:userdata:[pid=%u][serialid=%u][pading=%u][handle=%u]", pid,serialid,pading,handle);
						if (skynet_handle_grab(handle) == NULL)
						{
							this->gServerInst->CloseConnection(ep->second.m_GUID, true);
							break;
						}

						ep->second.m_Opraue = handle;
						connection_open(handle, guid);
						//                   sData.ReadBits((uint8_t*)&handle, sizeof(uint32_t)*8,false);

						skynet_error(NULL, "player register actor [handle=%d][serialid=%d][pid=%d][pading=%d][guid=%u]", handle, serialid, pid, pading, guid);

						//ack
						CMsgBuffer* newbuffer = this->getBuffer();
						RakNet::BitStream& pkg = newbuffer->pkg;
						pkg.Write((RakNet::MessageID)USER_DATA);
						char opt = 0x02;
						pkg.Write(opt);
						pkg.Write(pid);
						pkg.Write(serialid);
						pading = 0;
						pkg.Write(pading);
						this->gServerInst->Send(&newbuffer->pkg, HIGH_PRIORITY, RELIABLE_ORDERED, 0, Pak->systemAddress, false);
						newbuffer->pkg.Reset();
						this->PushBuffer(newbuffer);
					}
				}
				else
				{
					uint16_t pid = 0;
					uint32_t serialid = 0;
					sData.Read(pid);
					sData.Read(serialid);
					//skynet_error(NULL, "udpadapter:dispatchmsg:userdata:msg: [pid=%x][serialid=%d]", pid, serialid);

					if (serialid <= ep->second.m_SerialID)
					{
						break;
					}
					ep->second.m_SerialID = serialid;

					uint8_t totalpack = 0;
					uint8_t packindex = 0;
					sData.Read(totalpack);
					sData.Read(packindex);
					pos += 2;

					uint32_t recvsz = Pak->length - pos - 2;
					if(ep->second.m_RevLsPack == 0)
					{
						if((Pak->data[1] & 0x08) > 0)
						{
							if((totalpack < 2) || (packindex != 1))
							{
								break;
							}
							if(ep->second.m_RevTotalPack < totalpack)
							{
								if(ep->second.m_RevBuffer != NULL)
								{
									free(ep->second.m_RevBuffer);
								}
								ep->second.m_RevBuffer = (uint8_t*)malloc(totalpack * PACKAGE_PERSZ);
							}

							memcpy(ep->second.m_RevBuffer,Pak->data + pos + 2,recvsz);
							ep->second.m_RevSerial = serialid;
							ep->second.m_RevLsPack = packindex;
							ep->second.m_RevBuffPos = recvsz;
							ep->second.m_RevTotalPack = totalpack;
						}
						else
						{
							connection_read(ep->second.m_Opraue, guid, pid, Pak->data + pos + 2,recvsz);
						}
					}
					else
					{
						if(((Pak->data[1] & 0x08) == 0) || 
							(ep->second.m_RevSerial != serialid) || 
							(ep->second.m_RevLsPack + 1 != packindex) || 
							(packindex > totalpack) || 
							(ep->second.m_RevTotalPack != totalpack))
						{
							ep->second.m_RevSerial = 0;
							ep->second.m_RevLsPack = 0;
							ep->second.m_RevBuffPos = 0;	
							break;
						}

						memcpy(ep->second.m_RevBuffer + ep->second.m_RevBuffPos,Pak->data + pos + 2,recvsz);
						ep->second.m_RevBuffPos += recvsz;

						if(packindex == totalpack)
						{
							const uint8_t* tmpmsg = ep->second.m_RevBuffer;
							uint32_t tmpsz = ep->second.m_RevBuffPos;

							if((Pak->data[1] & 0x04) > 0)
							{
								static Bytef suncbuffer[STATIC_CACHE_SIZE] = {0};
								Bytef* cbuff = (Bytef*)tmpmsg;		
								uLongf srclen = tmpsz;

								uLongf distlen = STATIC_CACHE_SIZE;
								
								int ok = uncompress(suncbuffer,&distlen,cbuff,srclen);
								if(ok != Z_OK)
								{
									skynet_error(NULL,"udp uncompress error[%d]", ok);
									ep->second.m_RevSerial = 0;
									ep->second.m_RevLsPack = 0;		
									ep->second.m_RevBuffPos = 0;
									break;
								}
								tmpmsg = (const uint8_t*)suncbuffer;
								tmpsz = distlen;
							}

							connection_read(ep->second.m_Opraue, guid, pid, tmpmsg,tmpsz);

							ep->second.m_RevSerial = 0;
							ep->second.m_RevLsPack = 0;		
							ep->second.m_RevBuffPos = 0;
						}
						else
						{
							ep->second.m_RevLsPack = packindex;
						}
					}

				}
				pthread_rwlock_unlock(&m_RWLock);
			}
			break;

			default:
				skynet_error(NULL, "other msg type[%d]", pid);
				break;

			}
		}
	}
	catch(const std::exception& e)
	{
		std::cerr << e.what() << '\n';
		skynet_error(NULL,"DispatchMsg exception:%s", e.what());
	}

	//skynet_error(NULL,"DispatchMsg end");

	return 0;
}

void stUDPAdapter::RakAsyncSend()
{
	try
	{
		//skynet_error(NULL,"RakAsyncSend::threadid:before swap:[%x]", (unsigned int)pthread_self());
		this->swap();
		//skynet_error(NULL,"RakAsyncSend::threadid:after swap:[%x]", (unsigned int)pthread_self());
		for (auto it = this->m_Reader->begin(); it != this->m_Reader->end(); ++it)
		{
			CMsgBuffer* snedobj = *it;
			//skynet_error(NULL,"stUDPAdapter::RakAsyncSend:msgbuf:[handle=%u]", snedobj->handle);
			pthread_rwlock_rdlock(&m_RWLock);
			auto ep = this->m_MapRemote.find(snedobj->handle);
			if (ep != this->m_MapRemote.end())
			{
				//skynet_error(NULL,"stUDPAdapter::RakAsyncSend:mapremote:finded:[addr=%s]", ep->second.m_GUID.ToString(true));
				int recode = this->gServerInst->Send(&snedobj->pkg, HIGH_PRIORITY, RELIABLE_ORDERED, 0, ep->second.m_GUID, false);
				if (recode == 0)
				{
					skynet_error(NULL,"udp send error[%s]", ep->second.m_GUID.ToString(true));
				}
			}
			pthread_rwlock_unlock(&m_RWLock);

			snedobj->pkg.Reset();
			this->PushBuffer(snedobj);
		}

		this->m_Reader->clear();
	}
	catch(const std::exception& e)
	{
		std::cerr << e.what() << '\n';
		skynet_error(NULL,"RakAsyncSend exception:%s", e.what());
	}

	//skynet_error(NULL,"RakAsyncSend end");
}

int stUDPAdapter::Send(uint32_t handle, uint16_t pid, const void* msg, uint32_t len)
{
	//skynet_error(NULL,"stUDPAdapter::Send[handle=%u][pid=%x][msglen=%u]", handle, pid, len);

	int compr = 0;
	const char* tmpmsg = (const char*)msg;
	uint32_t sz = len;
	static uint32_t gSerialID = 1;
	uint32_t serial = gSerialID++;
	//skynet_error(NULL,"stUDPAdapter::Send[handle=%u][pid=%x][msglen=%u][gserialid=%u][serial=%u]", handle, pid, len, gSerialID, serial); 

	if (len > 1024 * 2)
	{
		compr = 1;

		static uLongf distlen = 0;
		static Bytef* buffer = NULL;
		static Bytef sbuffer[STATIC_CACHE_SIZE] = {0};

		uint32_t tlen = compressBound(len);

		Bytef* cbuff = NULL;
		if(STATIC_CACHE_SIZE < tlen)
		{
			if (buffer == NULL || distlen < tlen)
			{
				if(buffer != NULL)
				{
					free(buffer);
				}
				buffer = (Bytef*)malloc(tlen);
				distlen = tlen;
			}	
			cbuff = buffer;			
		}
		else
		{
			cbuff = sbuffer;
		}

		uLongf curdistlen = tlen;
		int r = compress(cbuff, &curdistlen, (const Bytef*)msg, (uLong)len);
		if (r != Z_OK)
		{
			skynet_error(NULL,"udp compress error[%d]", r);
			return -1;
		}

		tmpmsg = (const char*)cbuff;
		sz = curdistlen;
	}
	else if (len == 0)//为空
	{
		if (m_remoteHandler == pid) {
			CMsgBuffer* newbuffer = this->getBuffer();
			newbuffer->handle = handle;

			RakNet::BitStream& pkg = newbuffer->pkg;
			pkg.Write((RakNet::MessageID)USER_DATA);
			char opt = 0x01;
			uint16_t pading = 1;
			pkg.Write(opt);
			pkg.Write(pid);
			pkg.Write(serial);
			pkg.Write(pading);
			pkg.Write(m_remoteHandler);
			writeMsg(newbuffer);
		}
		else
		{
			CMsgBuffer* newbuffer = this->getBuffer();
			newbuffer->handle = handle;

			RakNet::BitStream& pkg = newbuffer->pkg;
			pkg.Write((RakNet::MessageID)USER_DATA);
			char opt = 0x00;
			uint8_t totalpack = 1;
			uint8_t packindex = 1;
			pkg.Write(opt);
			pkg.Write(pid);
			pkg.Write(serial);
			pkg.Write(totalpack);
			pkg.Write(packindex);
			writeMsg(newbuffer);
		}

		return 0;
	}

	uint8_t totalp = sz / PACKAGE_PERSZ + ((sz % PACKAGE_PERSZ) > 0 ? 1 : 0);
	uint8_t packindex = 1;
	while(sz > 0)
	{
		CMsgBuffer* newbuffer = this->getBuffer();
		newbuffer->handle = handle;

		RakNet::BitStream& pkg = newbuffer->pkg;
		pkg.Write((RakNet::MessageID)USER_DATA);	
		
		char opt = 0x00;
		if(compr == 1)
		{
			opt = 0x04;
		}
		if(totalp > 1)
		{
			opt |= 0x08;
		}
		pkg.Write(opt);
		pkg.Write(pid);
		pkg.Write(serial);
		pkg.Write(totalp);
		pkg.Write(packindex);
		uint32_t wsz = (sz < PACKAGE_PERSZ ? sz : PACKAGE_PERSZ);
		pkg.Write(tmpmsg, wsz);
		tmpmsg += wsz;
		writeMsg(newbuffer);
		//skynet_error(NULL,"stUDPAdapter:send:pak:[fd=%u][opt=%x][pid=%x][serial=%u][totalp=%u][packindex=%u][sz=%u][wsz=%u]", 
		//	handle, opt, pid, serial, totalp, packindex, sz, wsz);
		packindex++;

		if(sz < PACKAGE_PERSZ)
		{
			break;
		}
		sz -= PACKAGE_PERSZ;
	}		
	return 0;
}

int stUDPAdapter::shutdown(uint32_t guid)
{
	pthread_rwlock_rdlock(&m_RWLock);
	
	if (guid == 0) {
		this->m_MapRemote.clear();
		this->gServerInst->Shutdown(300);
	}
	else
	{
		auto ep = this->m_MapRemote.find(guid);
		if (ep == this->m_MapRemote.end())
		{
			pthread_rwlock_unlock(&m_RWLock);
			return -1;
		}
		this->gServerInst->CloseConnection(ep->second.m_GUID, true);
	}
	
	pthread_rwlock_unlock(&m_RWLock);
}

void stUDPAdapter::Ping()
{
	auto ep = this->m_MapRemote.begin();
	if (ep != this->m_MapRemote.end()) {
		//this->gServerInst->Ping(ep->second.m_GUID);
		bool isactive = this->gServerInst->IsActive();
		
		if (isactive) {
			CMsgBuffer* newbuffer = this->getBuffer();
			RakNet::BitStream& outBitStream = newbuffer->pkg;
			outBitStream.Write((MessageID)USER_PING);
			outBitStream.Write(RakNet::GetTime());

			this->gServerInst->Send(&newbuffer->pkg, IMMEDIATE_PRIORITY, UNRELIABLE, 0, ep->second.m_GUID, false);
			newbuffer->pkg.Reset();
			this->PushBuffer(newbuffer);
		}
		skynet_error(NULL, "stUDPAdapter:Ping:[%s][guid=%u][clienthandle=%u][isactive=%d]", ep->second.m_GUID.ToString(true), ep->first, m_handle, isactive);
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////
bool g_Init = false;
bool g_RakRunable = false;
stUDPAdapter* g_RakAdapter = NULL;
std::unordered_map<uint32_t, stUDPAdapter*> g_mapRakClient;

void closefd(uint32_t fd)
{
	if(g_RakAdapter)
		g_RakAdapter->shutdown(fd);
}

void* rak_async_send(void* param)
{
	try
	{
		if (param) {
			stUDPAdapter * tmpadapter = (stUDPAdapter*)param;
			uint32_t handle = tmpadapter->m_handle;
			skynet_error(NULL,"rak_async_send[%x]", handle);
			while(tmpadapter) {
				//skynet_error(NULL,"rak_async_send:RakAsyncSend[%x]", handle);
				tmpadapter->RakAsyncSend();
				RakSleep(30);
			}
		}
		else
		{
			while (g_RakRunable)
			{
				//skynet_error(NULL,"rak_async_send:RakAsyncSend");
				if (g_RakAdapter)
					g_RakAdapter->RakAsyncSend();
				RakSleep(30);
			}
			g_RakAdapter->RakAsyncSend();
		}
	}
	catch(const std::exception& e)
	{
		std::cerr << e.what() << '\n';
		skynet_error(NULL,"rak_async_send exception:%s", e.what());
	}
	
	//skynet_error(NULL,"rak_async_send:thread end");
	return NULL;
}

void* rak_async_revc(void* param)
{
	try
	{
		if (param) {
			stUDPAdapter * tmpadapter = (stUDPAdapter*)param;
			uint32_t handle = tmpadapter->m_handle;
			skynet_error(NULL,"rak_async_revc[%x]", handle);
			while(tmpadapter) {
				//skynet_error(NULL,"rak_async_revc:DispatchMsg[%x]", handle);
				tmpadapter->DispatchMsg();
				RakSleep(30);
			}
		}
		else
		{
			while (g_RakRunable)
			{
				//skynet_error(NULL,"rak_async_revc:DispatchMsg");
				if (g_RakAdapter)
					g_RakAdapter->DispatchMsg();
				RakSleep(30);
			}
			if (g_RakAdapter)
				g_RakAdapter->DispatchMsg();
		}
	}
	catch(const std::exception& e)
	{
		std::cerr << e.what() << '\n';
		skynet_error(NULL,"rak_async_revc exception:%s", e.what());
	}
	
	//skynet_error(NULL,"rak_async_revc:thread end");
	return NULL;
}

void init(uint16_t port, const char* conPwd)
{
	if(!g_Init)
	{
		g_Init = true;
		if (g_RakAdapter == NULL)
		{
			g_RakAdapter = new stUDPAdapter();
			g_RakAdapter->start(port, conPwd);
		}
			
		g_RakRunable = true;

		pthread_t pid;
		pthread_create(&pid, NULL, rak_async_send, NULL);
		pthread_create(&pid, NULL, rak_async_revc, NULL);
	}
}

void rak_send(uint32_t index, uint32_t handle, uint16_t pid, const void* msg, uint32_t len)
{
	//skynet_error(NULL,"rak_send:[index=%u][handle=%u][pid=%x][len=%u]", index, handle, pid, len);
	if (index > 0) {
		stUDPAdapter* tmp = g_mapRakClient[index];
		if (tmp) {
			tmp->Send(handle, pid, msg, len);
		}
	}
	else
	{
		if (g_RakAdapter != NULL)
			g_RakAdapter->Send(handle, pid, msg, len);
	}
}

void rak_ping(uint32_t index)
{
	if (index > 0) {
		stUDPAdapter* tmp = g_mapRakClient[index];
		if (tmp) {
			tmp->Ping();
		}
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////
void NewClient(uint32_t handle, const char* ip, uint16_t port, const char* conPwd, uint32_t remoteHandler)
{
	stUDPAdapter* adapter = new stUDPAdapter();
	adapter->clientMode(handle, ip, port, conPwd, remoteHandler);
	//skynet_error(NULL,"map insert");
	g_mapRakClient.insert(std::pair<uint32_t, stUDPAdapter*>(handle, adapter));
	//skynet_error(NULL,"thread create");

	pthread_t pid;
	pthread_create(&pid, NULL, rak_async_send, adapter);
	pthread_create(&pid, NULL, rak_async_revc, adapter);
	//skynet_error(NULL,"rak_async_revc create");

	//skynet_error(NULL,"rak_async_send create");

}

void CloseClient(uint32_t handle)
{
	stUDPAdapter* tmp = g_mapRakClient[handle];
	g_mapRakClient.erase(handle);
	tmp->shutdown(0);
}