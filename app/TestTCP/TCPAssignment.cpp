/*
 * E_TCPAssignment.cpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: 근홍
 */


#include <E/E_Common.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_Networking.hpp>
#include <cerrno>
#include <E/Networking/E_Packet.hpp>
#include <E/Networking/E_NetworkUtil.hpp>
#include "TCPAssignment.hpp"
#include <E/Networking/E_RoutingInfo.hpp>
#include <list>

#define FIN_FLAG 0x01
#define SYN_FLAG 0x02
#define RST_FLAG 0x04
#define PSH_FLAG 0x08			/* generally not used. */
#define ACK_FLAG 0x10
#define URG_FLAG 0x20			/* generally not used. */
#define MSL 60000
#define ALPHA (double) 0.125
#define BETA (double) 0.25

namespace E
{

TCPAssignment::TCPAssignment(Host* host) : HostModule("TCP", host),
		NetworkModule(this->getHostModuleName(), host->getNetworkSystem()),
		SystemCallInterface(AF_INET, IPPROTO_TCP, host),
		NetworkLog(host->getNetworkSystem()),
		TimerModule(host->getSystem())
{

}

TCPAssignment::~TCPAssignment()
{

}

void TCPAssignment::initialize()
{

}

void TCPAssignment::finalize()
{

}

void TCPAssignment::systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param)
{
	switch(param.syscallNumber)
	{
	case SOCKET:
		this->syscall_socket(syscallUUID, pid, param.param1_int, param.param2_int);
		break;
	case CLOSE:
		this->syscall_close(syscallUUID, pid, param.param1_int);
		break;
	case READ:
		//this->syscall_read(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case WRITE:
		this->syscall_write(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case CONNECT:
		this->syscall_connect(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr*>(param.param2_ptr), (socklen_t)param.param3_int);
		break;
	case LISTEN:
		this->syscall_listen(syscallUUID, pid, param.param1_int, param.param2_int);
		break;
	case ACCEPT:
		this->syscall_accept(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr*>(param.param2_ptr),
				static_cast<socklen_t*>(param.param3_ptr));
		break;
	case BIND:
		this->syscall_bind(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				(socklen_t) param.param3_int);
		break;
	case GETSOCKNAME:
		this->syscall_getsockname(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				static_cast<socklen_t*>(param.param3_ptr));
		break;
	case GETPEERNAME:
		this->syscall_getpeername(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				static_cast<socklen_t*>(param.param3_ptr));
		break;
	default:
		assert(0);
	}
}

/* System Call Implementation */
void TCPAssignment::syscall_socket (UUID syscallUUID, int pid, int type, int protocol)
{
	int sockfd = this->createFileDescriptor (pid);
	this->returnSystemCall (syscallUUID, sockfd);
}

void TCPAssignment::syscall_close (UUID syscallUUID, int pid, int fd)
{
	std::list< struct tcp_context >::iterator cursor;
	cursor = this->find_tcp_context (pid, fd);

	if (cursor == this->tcp_context_list.end ())
		this->returnSystemCall (syscallUUID, -1);
	
	if (cursor->tcp_state == E::ESTABLISHED)
	{
		int seq_num = htonl (this->random_seq_num);
		uint8_t hdr_len = 0x50;
		uint8_t sending_flag = 0x0 | FIN_FLAG;
		unsigned short checksum = 0;
		struct tcp_header tmp_header;

		/* Send FIN packet and enter the FIN_WAIT_1 state */
		Packet *fin_packet = this->allocatePacket (54);
		
		fin_packet->writeData (26, &cursor->src_addr, 4);
		fin_packet->writeData (30, &cursor->dst_addr, 4);
		fin_packet->writeData (34, &cursor->src_port, 2);
		fin_packet->writeData (36, &cursor->dst_port, 2);
		fin_packet->writeData (38, &seq_num, 4);
		fin_packet->writeData (46, &hdr_len, 1);
		fin_packet->writeData (47, &sending_flag, 1);
		fin_packet->writeData (50, &checksum, 2);

		fin_packet->readData (34, &tmp_header, 20);
		checksum = this->calculate_checksum (cursor->src_addr, cursor->dst_addr, tmp_header);
		fin_packet->writeData (50, &checksum, 2);

		cursor->seq_num = this->random_seq_num++;
		cursor->tcp_state = E::FIN_WAIT_1;
		cursor->wake_args.syscallUUID = syscallUUID;

		this->sendPacket ("IPv4", fin_packet);
		return;
	}

	else if (cursor->tcp_state == E::CLOSE_WAIT)
	{
		int seq_num = htonl (this->random_seq_num);
		uint8_t hdr_len = 0x50;
		uint8_t sending_flag = 0x0 | FIN_FLAG;
		unsigned short checksum = 0;
		struct tcp_header tmp_header;

		Packet *fin_packet = this->allocatePacket (54);

		fin_packet->writeData (26, &cursor->src_addr, 4);
		fin_packet->writeData (30, &cursor->dst_addr, 4);
		fin_packet->writeData (34, &cursor->src_port, 2);
		fin_packet->writeData (36, &cursor->dst_port, 2);
		fin_packet->writeData (38, &seq_num, 4);
		fin_packet->writeData (46, &hdr_len, 1);
		fin_packet->writeData (47, &sending_flag, 1);
		fin_packet->writeData (50, &checksum, 2);

		fin_packet->readData (34, &tmp_header, 20);
		checksum = this->calculate_checksum (cursor->src_addr, cursor->dst_addr, tmp_header);
		fin_packet->writeData (50, &checksum, 2);

		cursor->seq_num = this->random_seq_num++;
		cursor->tcp_state = E::LAST_ACK;
		cursor->wake_args.syscallUUID = syscallUUID;

		this->sendPacket ("IPv4", fin_packet);
		return;
	}

	else
	{
		this->remove_tcp_context (pid, fd);
		this->removeFileDescriptor (pid, fd);
		this->returnSystemCall (syscallUUID, 0);
	}
}

void TCPAssignment::syscall_write (UUID syscallUUID, int pid, int sockfd, const void *send_buffer, int length)
{
	std::list< struct tcp_context >::iterator current_context = find_tcp_context (pid, sockfd);

	if (current_context->tcp_state != E::ESTABLISHED)
	{
		fprintf (stderr, "here!!\n");
		return;
	}

	int remain_bytes = 0;
	int sent_bytes = 0;

	if (length > this->MSS * 5)
		remain_bytes = this->MSS * 5;
	else
		remain_bytes = length;

	while (remain_bytes != 0)
	{
		int loop = 0;
		int sending_bytes = 0;

		if ((sending_bytes = this->MSS) > remain_bytes)
			sending_bytes = remain_bytes;

		int seq_num = htonl (current_context->seq_num);
		int sending_flag = 0x0;
		uint8_t hdr_len = 0x50;
		unsigned short checksum = 0;
		struct tcp_header tmp_header;

		fprintf (stderr, "breakpoint 1\n");
		Packet *data_packet = this->allocatePacket (54 + sending_bytes);

		data_packet->writeData (26, &current_context->src_addr, 4);
		data_packet->writeData (30, &current_context->dst_addr, 4);
		data_packet->writeData (34, &current_context->src_port, 2);
		data_packet->writeData (36, &current_context->dst_port, 2);
		data_packet->writeData (38, &seq_num, 4);
		data_packet->writeData (46, &hdr_len, 1);
		data_packet->writeData (47, &sending_flag, 1);
		data_packet->writeData (50, &checksum, 2);

		data_packet->readData (34, &tmp_header, 20);
		checksum = this->calculate_checksum (current_context->src_addr, current_context->dst_addr, tmp_header);
		data_packet->writeData (50, &checksum, 2);
		fprintf (stderr, "breakpoint 2\n");
		data_packet->writeData (54, (uint8_t *) send_buffer + sent_bytes, sending_bytes);

		seq_num = ntohl (seq_num);

		struct sent_packet sent_pkt;
		sent_pkt.packet = this->clonePacket (data_packet);
		sent_pkt.sent_seq = seq_num;
		sent_pkt.expect_ack = seq_num + sending_bytes;
		sent_pkt.data_start = sent_bytes;
		sent_pkt.data_length = sending_bytes;
		fprintf (stderr, "breakpoint 3\n");
		sent_pkt.sent_time = this->getHost ()->getSystem ()->getCurrentTime ();

		// add timer only for first packet 
		if (loop == 0)	
		{
			UUID timerUUID;
			/* timer */
			struct timer_arguments *timer_args = (struct timer_arguments *) malloc (sizeof (struct timer_arguments));																									
			timer_args->pid = current_context->pid;
			timer_args->sockfd = current_context->sockfd;
			timer_args->seq_num = seq_num;
			double timeoutInterval = get_timeout_interval (current_context);				

			timerUUID = this->addTimer ((void *) timer_args, this->getHost ()->getSystem ()->getCurrentTime () + timeoutInterval);

			current_context->transfer_timerUUID = timerUUID;									
		}

		this->sendPacket ("IPv4", data_packet);
		fprintf (stderr, "breakpoint 4\n");
		current_context->sent_packet_list.push_back (sent_pkt);
		fprintf (stderr, "breakpoint 5\n");

		remain_bytes -= sending_bytes;
		sent_bytes += sending_bytes;
		current_context->seq_num += sending_bytes;
		loop++;
		fprintf (stderr, "remain bytes: %d, sent_bytes: %d\n", remain_bytes, sent_bytes);
	}

	current_context->wake_args.syscallUUID = syscallUUID;
	return;
}

void TCPAssignment::syscall_connect (UUID syscallUUID, int pid, int sockfd, struct sockaddr *serv_addr, socklen_t addrlen)
{
	std::list< struct tcp_context >::iterator entry = this->find_tcp_context (pid, sockfd);
	struct sockaddr_in *serv_addr_v4 = (struct sockaddr_in *) serv_addr;

	/* not yet bound, so we bind implicitly. */
	if (entry == this->tcp_context_list.end ())
	{
		std::list< struct tcp_context >::iterator cursor;
		for (cursor = this->tcp_context_list.begin (); cursor != this->tcp_context_list.end (); cursor++)
		{
			if (cursor->pid == pid && cursor->sockfd == sockfd)		
				return;
			
			if ((cursor->src_addr == INADDR_ANY) && cursor->src_port == htons (this->random_port))
				return;
		}

		unsigned int local_ip;
		struct tcp_context new_context;
		int interface = this->getHost ()->getRoutingTable ((uint8_t *) &serv_addr_v4->sin_addr.s_addr);
		this->getHost ()->getIPAddr ((uint8_t *) &local_ip, interface);

		new_context.pid = pid;
		new_context.sockfd = sockfd;
		new_context.src_addr = local_ip;
		new_context.src_port = htons (this->random_port++);
		new_context.is_bound = true;

		this->tcp_context_list.push_back (new_context);
		entry = this->find_tcp_context (pid, sockfd);
	}

	int seq_num = htonl (this->random_seq_num);
	int sending_flag = 0x0 | SYN_FLAG;
	uint8_t hdr_len = 0x50;
	unsigned short checksum = 0;
	struct tcp_header tmp_header;

	/* sending SYN packet */
	Packet *syn_packet = this->allocatePacket (54);

	syn_packet->writeData (26, &entry->src_addr, 4);
	syn_packet->writeData (30, &(serv_addr_v4->sin_addr.s_addr), 4);
	syn_packet->writeData (34, &entry->src_port, 2);
	syn_packet->writeData (36, &(serv_addr_v4->sin_port), 2);
	syn_packet->writeData (38, &seq_num, 4);
	syn_packet->writeData (46, &hdr_len, 1);
	syn_packet->writeData (47, &sending_flag, 1);
	syn_packet->writeData (50, &checksum, 2);

	syn_packet->readData (34, &tmp_header, 20);
	checksum = this->calculate_checksum (entry->src_addr, serv_addr_v4->sin_addr.s_addr, tmp_header);
	syn_packet->writeData (50, &checksum, 2);

	this->sendPacket ("IPv4", syn_packet);

	/* Update TCP Context */
	entry->dst_addr = serv_addr_v4->sin_addr.s_addr;
	entry->dst_port = serv_addr_v4->sin_port;
	entry->tcp_state = E::SYN_SENT;
	entry->seq_num = this->random_seq_num++;

	/* Remember the current context */
	entry->wake_args.syscallUUID = syscallUUID;
	entry->wake_args.addr = serv_addr;
}

void TCPAssignment::syscall_listen (UUID syscallUUID, int pid, int sockfd, int backlog)
{
	std::list< struct tcp_context >::iterator entry = this->find_tcp_context (pid, sockfd);
	if (entry == tcp_context_list.end ())
		returnSystemCall (syscallUUID, -1);
	
	else
	{
		if (!entry->is_bound)
			returnSystemCall (syscallUUID, -1);

		else
		{
			entry->tcp_state = E::LISTEN;
			entry->backlog = backlog;
			returnSystemCall (syscallUUID, 0);
		}
	}
}

void TCPAssignment::syscall_accept (UUID syscallUUID, int pid, int listenfd, struct sockaddr *addr, socklen_t *addrlen)
{
	std::list< struct tcp_context >::iterator entry = this->find_tcp_context (pid, listenfd);

	if (entry == this->tcp_context_list.end ())
		this->returnSystemCall (syscallUUID, -1);

	else
	{
		if (entry->tcp_state != E::LISTEN)
			this->returnSystemCall (syscallUUID, -1);

		else
		{
			if (entry->estab_conn_list.empty ())
			{
				entry->wake_args.syscallUUID = syscallUUID;
				entry->wake_args.addr = addr;
				entry->wake_args.addrlen = addrlen;
				entry->to_be_accepted++;
				return;
			}

			else
			{
				int connfd = this->createFileDescriptor (pid);
				struct tcp_context estab_context = entry->estab_conn_list.front ();
				entry->estab_conn_list.pop_front ();
				estab_context.pid = pid;
				estab_context.sockfd = connfd;
				((struct sockaddr_in *) addr)->sin_family = AF_INET;
				((struct sockaddr_in *) addr)->sin_addr.s_addr = estab_context.src_addr;
				((struct sockaddr_in *) addr)->sin_port = estab_context.src_port;
				this->tcp_context_list.push_back (estab_context);
				this->returnSystemCall (syscallUUID, connfd);
			}
		}
	}
}

void TCPAssignment::syscall_bind (UUID syscallUUID, int pid, int sockfd, struct sockaddr *my_addr, socklen_t addrlen)
{
	struct sockaddr_in *my_addr_v4 = (struct sockaddr_in *) my_addr;
	struct sockaddr *entry = (struct sockaddr *) malloc (sizeof (struct sockaddr));
	memcpy (entry, my_addr, sizeof (struct sockaddr));
	std::list< struct tcp_context >::iterator cursor;

	for (cursor = this->tcp_context_list.begin (); cursor != this->tcp_context_list.end (); cursor++)
	{
		if (cursor->pid == pid && cursor->sockfd == sockfd)
			this->returnSystemCall (syscallUUID, -1);

		if (my_addr_v4->sin_port == cursor->src_port)
		{
			if (cursor->src_addr == my_addr_v4->sin_addr.s_addr ||
				 cursor->src_addr == INADDR_ANY ||
				 my_addr_v4->sin_addr.s_addr == INADDR_ANY)
				this->returnSystemCall (syscallUUID, -1);
		}
	}

	struct tcp_context new_context;
	new_context.pid = pid;
	new_context.sockfd = sockfd;
	new_context.src_addr = my_addr_v4->sin_addr.s_addr;
	new_context.src_port = my_addr_v4->sin_port;
	new_context.is_bound = true;

	this->tcp_context_list.push_back (new_context);
	this->returnSystemCall (syscallUUID, 0);
}
	
void TCPAssignment::syscall_getsockname (UUID syscallUUID, int pid, int sockfd, struct sockaddr *name, socklen_t *namelen_t)
{
	std::list< struct tcp_context >::iterator entry = this->find_tcp_context (pid, sockfd);

	/* No such socket in the list */
	if (entry == this->tcp_context_list.end ())
		this->returnSystemCall (syscallUUID, -1);

	else
	{
		((struct sockaddr_in *) name)->sin_family = AF_INET;
		((struct sockaddr_in *) name)->sin_port = entry->src_port;
		((struct sockaddr_in *) name)->sin_addr.s_addr = entry->src_addr;
		*namelen_t = sizeof (struct sockaddr);
		this->returnSystemCall (syscallUUID, 0);
	}
}

void TCPAssignment::syscall_getpeername (UUID syscallUUID, int pid, int sockfd, struct sockaddr *name, socklen_t *namelen_t)
{
	std::list< struct tcp_context >::iterator entry = this->find_tcp_context (pid, sockfd);

	if (entry == this->tcp_context_list.end ())
		this->returnSystemCall (syscallUUID, -1);

	else
	{
		((struct sockaddr_in *) name)->sin_family = AF_INET;
		((struct sockaddr_in *) name)->sin_port = entry->dst_port;
		((struct sockaddr_in *) name)->sin_addr.s_addr = entry->dst_addr;
		*namelen_t = sizeof (struct sockaddr);
		this->returnSystemCall (syscallUUID, 0);
	}
}

/* Packet Arrived */
void TCPAssignment::packetArrived(std::string fromModule, Packet* packet)
{
	unsigned int src_addr;
	unsigned int dst_addr;
	unsigned short checksum = 0;
	uint8_t IHL;
	int recv_seq_num, recv_ack_num;
	bool FIN, SYN, ACK;
	
	/* For TCP Header */
	struct tcp_header *recv_tcp_header = (struct tcp_header *) malloc (sizeof (struct tcp_header));
	recv_tcp_header->checksum = 0;
	packet->readData (14, &IHL, 1);
	packet->readData (26, &src_addr, 4);
	packet->readData (30, &dst_addr, 4);
	IHL = IHL & 0x0f;
	packet->readData (14 + IHL*4, recv_tcp_header, 20);
	FIN = bool (recv_tcp_header->flags & FIN_FLAG);
	SYN = bool (recv_tcp_header->flags & SYN_FLAG);
	ACK = bool (recv_tcp_header->flags & ACK_FLAG);
	recv_seq_num = ntohl (recv_tcp_header->seq_num);
	recv_ack_num = ntohl (recv_tcp_header->ack_num);

	std::list< struct tcp_context >::iterator current_context;
	TCP_STATE state = E::CLOSED;

	current_context = get_context_addr_port (src_addr, dst_addr, recv_tcp_header->src_port, recv_tcp_header->dst_port);

	if (current_context != this->tcp_context_list.end ())
		state = current_context->tcp_state;

	switch (state)
	{
		case E::LISTEN:
		{
			if (SYN)
			{
				if (current_context->pending_conn_list.size () >= current_context->backlog)
				{
					this->freePacket (packet);
					return;
				}

				struct tcp_context new_context;
				int seq_num = htonl (this->random_seq_num);
				int ack_num = htonl (recv_seq_num + 1);
				uint8_t sending_flag = 0x0 | SYN_FLAG | ACK_FLAG;
				unsigned short checksum = 0;
				struct tcp_header tmp_header;

				new_context.src_addr = dst_addr;
				new_context.dst_addr = src_addr;
				new_context.src_port = recv_tcp_header->dst_port;
				new_context.dst_port = recv_tcp_header->src_port;
				new_context.seq_num = this->random_seq_num++;
				new_context.tcp_state = E::SYN_RCVD;
				current_context->pending_conn_list.push_back (new_context);

				/* send SYNACK packet */
				Packet *syn_ack_packet = this->clonePacket (packet);

				syn_ack_packet->writeData (26, &dst_addr, 4);
				syn_ack_packet->writeData (30, &src_addr, 4);
				syn_ack_packet->writeData (34, &recv_tcp_header->dst_port, 2);
				syn_ack_packet->writeData (36, &recv_tcp_header->src_port, 2);
				syn_ack_packet->writeData (38, &seq_num, 4);
				syn_ack_packet->writeData (42, &ack_num, 4);
				syn_ack_packet->writeData (47, &sending_flag, 1);
				syn_ack_packet->writeData (50, &checksum, 2);

				syn_ack_packet->readData (34, &tmp_header, 20);
				checksum = this->calculate_checksum (dst_addr, src_addr, tmp_header);
				syn_ack_packet->writeData (50, &checksum, 2);

				this->sendPacket ("IPv4", syn_ack_packet);
			}

			/* Actually SYN_RCVD */
			if (ACK)
			{
				std::list< struct tcp_context >::iterator entry;
				struct tcp_context new_context;
				entry = this->find_pending_context (recv_ack_num - 1, &current_context->pending_conn_list);
				new_context = *entry;

				current_context->pending_conn_list.erase (entry);
				new_context.tcp_state = E::ESTABLISHED;
				current_context->estab_conn_list.push_back (new_context);

				if (current_context->to_be_accepted)
				{
					current_context->to_be_accepted--;
					int connfd;
					struct tcp_context estab_context = current_context->estab_conn_list.front ();
					struct sockaddr_in *addr_v4 = (struct sockaddr_in *) current_context->wake_args.addr;
					current_context->estab_conn_list.pop_front ();
					connfd = this->createFileDescriptor (current_context->pid);
					estab_context.pid = current_context->pid;
					estab_context.sockfd = connfd;
					addr_v4->sin_family = AF_INET;
					addr_v4->sin_addr.s_addr = estab_context.src_addr;
					addr_v4->sin_port = estab_context.src_port;
					this->tcp_context_list.push_back (estab_context);
					this->returnSystemCall (current_context->wake_args.syscallUUID, connfd);
				}
			}
		}
		break;

		case E::SYN_SENT:
		{
			if (SYN)
			{
				int ack_num = htonl (recv_seq_num + 1);
				uint8_t sending_flag = 0x0 | ACK_FLAG;
				unsigned short checksum = 0;
				struct tcp_header tmp_header;

				Packet *ack_packet = this->clonePacket (packet);

				ack_packet->writeData (26, &dst_addr, 4);
				ack_packet->writeData (30, &src_addr, 4);
				ack_packet->writeData (34, &recv_tcp_header->dst_port, 2);
				ack_packet->writeData (36, &recv_tcp_header->src_port, 2);
				ack_packet->writeData (42, &ack_num, 4);
				ack_packet->writeData (47, &sending_flag, 1);
				ack_packet->writeData (50, &checksum, 2);

				ack_packet->readData (34, &tmp_header, 20);
				checksum = this->calculate_checksum (dst_addr, src_addr, tmp_header);
				ack_packet->writeData (50, &checksum, 2);

				this->sendPacket ("IPv4", ack_packet);
			}

			if (ACK)
			{
				if (recv_ack_num - 1 == current_context->seq_num)
				{
					current_context->tcp_state = E::ESTABLISHED;
					this->returnSystemCall (current_context->wake_args.syscallUUID, 0);
				}
				
				else
					this->returnSystemCall (current_context->wake_args.syscallUUID, -1);
			}
		}
		break;

		case E::ESTABLISHED:
		{
			if (FIN)
			{
				/* this is server-side and send ACK packet */
				uint8_t hdr_len = 0x50;
				uint8_t sending_flag = 0x0 | FIN_FLAG;
				unsigned short checksum = 0;
				struct tcp_header tmp_header;
				
				Packet *ack_packet = this->allocatePacket (54);
				
				ack_packet->writeData (26, &dst_addr, 4);
				ack_packet->writeData (30, &src_addr, 4);
				ack_packet->writeData (34, &recv_tcp_header->dst_port, 2);
				ack_packet->writeData (36, &recv_tcp_header->src_port, 2);
				ack_packet->writeData (46, &hdr_len, 1);
				ack_packet->writeData (47, &sending_flag, 1);
				ack_packet->writeData (50, &checksum, 2);
				
				ack_packet->readData (34, &tmp_header, 20);
				checksum = calculate_checksum (dst_addr, src_addr, tmp_header);
				ack_packet->writeData (50, &checksum, 2);

				current_context->tcp_state = E::CLOSE_WAIT;
				this->sendPacket ("IPv4", ack_packet);
			}

			if (ACK)
				fprintf (stderr, "########### success ##########\n");
		}
		break;

		case E::FIN_WAIT_1:
		{
			if (ACK)
				current_context->tcp_state = E::FIN_WAIT_2;

			if (FIN)
			{
				int ack_num = htonl (recv_seq_num + 1);
				uint8_t sending_flag = 0x0 | ACK_FLAG;
				unsigned short checksum = 0;
				struct tcp_header tmp_header;
				Packet *ack_packet = this->clonePacket (packet);

				ack_packet->writeData (26, &dst_addr, 4);
				ack_packet->writeData (30, &src_addr, 4);
				ack_packet->writeData (34, &recv_tcp_header->dst_port, 2);
				ack_packet->writeData (36, &recv_tcp_header->src_port, 2);
				ack_packet->writeData (42, &ack_num, 4);
				ack_packet->writeData (47, &sending_flag, 1);
				ack_packet->writeData (50, &checksum, 2);

				ack_packet->readData (34, &tmp_header, 20);
				checksum = calculate_checksum (dst_addr, src_addr, tmp_header);
				ack_packet->writeData (50, &checksum, 2);
				this->sendPacket ("IPv4", ack_packet);

				if (current_context->tcp_state == E::FIN_WAIT_2)
				{
					current_context->tcp_state = TIME_WAIT;

					/* Timer */
					struct timer_arguments *timer_args = (struct timer_arguments *) malloc (sizeof (struct timer_arguments));
					timer_args->pid = current_context->pid;
					timer_args->sockfd = current_context->sockfd;

					this->addTimer ((void *) timer_args, this->getHost ()->getSystem ()->getCurrentTime () + 2 * MSL);
					this->removeFileDescriptor (current_context->pid, current_context->sockfd);
				}

				else if (current_context->tcp_state == E::FIN_WAIT_1)
					current_context->tcp_state = CLOSING;
			}
		}
		break;

		case E::FIN_WAIT_2:
		{
			if (FIN)
			{
				int ack_num = htonl (recv_seq_num + 1);
				uint8_t sending_flag = 0x0 | ACK_FLAG;
				unsigned short checksum = 0;
				struct tcp_header tmp_header;

				Packet *ack_packet = this->clonePacket (packet);

				ack_packet->writeData (14+12, &dst_addr, 4);
				ack_packet->writeData (14+16, &src_addr, 4);
				ack_packet->writeData (34, &recv_tcp_header->dst_port, 2);
				ack_packet->writeData (36, &recv_tcp_header->src_port, 2);
				ack_packet->writeData (42, &ack_num, 4);
				ack_packet->writeData (47, &sending_flag, 1);
				ack_packet->writeData (50, &checksum, 2);

				ack_packet->readData (34, &tmp_header, 20);
				checksum = this->calculate_checksum (dst_addr, src_addr, tmp_header);
				ack_packet->writeData (50, &checksum, 2);

				current_context->tcp_state = E::TIME_WAIT;

				this->sendPacket ("IPv4", ack_packet);

				/* Timer */
				struct timer_arguments *timer_args = (struct timer_arguments *) malloc (sizeof (struct timer_arguments));
				timer_args->pid = current_context->pid;
				timer_args->sockfd = current_context->sockfd;

				this->addTimer ((void *) timer_args, this->getHost ()->getSystem ()->getCurrentTime () + 2 * MSL);
				this->removeFileDescriptor (current_context->pid, current_context->sockfd);
			}
		}
		break;

		case E::CLOSING:
		{
			if (ACK)
			{
				current_context->tcp_state = E::TIME_WAIT;

				/* Timer */
				struct timer_arguments *timer_args = (struct timer_arguments *) malloc (sizeof (struct timer_arguments));
				timer_args->pid = current_context->pid;
				timer_args->sockfd = current_context->sockfd;

				this->addTimer ((void *) timer_args, this->getHost ()->getSystem ()->getCurrentTime () + 2 * MSL);
				this->removeFileDescriptor (current_context->pid, current_context->sockfd);
			}
		}
		break;

		case E::LAST_ACK:
		{
			if (ACK)
			{
				if (current_context->seq_num == recv_ack_num - 1)
				{
					current_context->tcp_state = E::CLOSED;
					this->remove_tcp_context (current_context->pid, current_context->sockfd);
					this->removeFileDescriptor (current_context->pid, current_context->sockfd);
					this->returnSystemCall (current_context->wake_args.syscallUUID, 0);
				}
			}
		}
		break;

		case E::TIME_WAIT:
		{
			if (FIN)
			{
				int ack_num = htonl (recv_seq_num + 1);
				uint8_t sending_flag = 0x0 | ACK_FLAG;
				unsigned short checksum = 0;
				struct tcp_header tmp_header;

				/* retrasmit ACK packet */
				Packet *ack_packet = this->clonePacket (packet);

				ack_packet->writeData (26, &dst_addr, 4);
				ack_packet->writeData (30, &src_addr, 4);
				ack_packet->writeData (34, &recv_tcp_header->dst_port, 2);
				ack_packet->writeData (36, &recv_tcp_header->src_port, 2);
				ack_packet->writeData (42, &ack_num, 1);
				ack_packet->writeData (47, &sending_flag, 1);
				ack_packet->writeData (50, &checksum, 2);
				
				ack_packet->readData (34, &tmp_header, 20);
				checksum = calculate_checksum (dst_addr, src_addr, tmp_header);
				ack_packet->writeData (50, &checksum, 2);

				this->sendPacket ("IPv4", ack_packet);
			}
		}
		break;

		case E::CLOSED:
		{

		}
		break;
		
		default:
			break;
	}

	free (recv_tcp_header);
	this->freePacket (packet);
}

void TCPAssignment::timerCallback(void* payload)
{
	std::list< struct tcp_context >::iterator entry = this->find_tcp_context (((struct timer_arguments *) payload)->pid, ((struct timer_arguments *) payload)->sockfd);

	entry->tcp_state = E::CLOSED;
	UUID retUUID = entry->wake_args.syscallUUID;
	this->remove_tcp_context (entry->pid, entry->sockfd);
	free ((struct timer_arguments *) payload);
	this->returnSystemCall (retUUID, 0);
}

/* Helper */
struct pseudo_header
{
	struct in_addr src_addr;
	struct in_addr dst_addr;
	uint8_t reserved;
	uint8_t protocol;
	unsigned short length;
	struct tcp_header tcpheader;
}__attribute__((packed));

unsigned short TCPAssignment::calculate_checksum (unsigned int src, unsigned int dst, struct tcp_header theader)
{
	uint32_t sum = 0;

	struct pseudo_header pheader;
	pheader.src_addr.s_addr = src;
	pheader.dst_addr.s_addr = dst;
	pheader.reserved = 0;
	pheader.protocol = IPPROTO_TCP;
	pheader.length = htons (sizeof (struct tcp_header));
	memcpy (&pheader.tcpheader, &theader, sizeof (struct tcp_header));

	unsigned short *buf = (unsigned short *) &pheader;
	int len = sizeof (struct pseudo_header) / sizeof (unsigned short);

	while (len--)
		sum += *buf++;

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);

	return (unsigned short) (~sum);
}

std::list< struct tcp_context >::iterator TCPAssignment::find_tcp_context (int pid, int sockfd)
{
	std::list< struct tcp_context >::iterator cursor;

	for (cursor = this->tcp_context_list.begin (); cursor != this->tcp_context_list.end (); ++cursor)
	{
		if (cursor->pid == pid && cursor->sockfd == sockfd)
			return cursor;
	}

	return cursor;
}

std::list< struct tcp_context >::iterator TCPAssignment::get_context_addr_port (unsigned int src_addr, unsigned int dst_addr, unsigned short src_port, unsigned short dst_port)
{
	std::list< struct tcp_context >::iterator cursor;

	for (cursor = this->tcp_context_list.begin (); cursor != this->tcp_context_list.end (); ++cursor)
	{
		if ((cursor->src_addr == dst_addr || cursor->src_addr == 0) &&
			 cursor->dst_addr == src_addr &&
			 cursor->src_port == dst_port &&
			 cursor->dst_port == src_port)
			return cursor;
	}

	for (cursor = this->tcp_context_list.begin (); cursor != this->tcp_context_list.end (); ++cursor)
	{
		if ((cursor->src_addr == dst_addr || cursor->src_addr == 0xb123456 || cursor->src_addr == 0) && cursor->src_port == dst_port)
			return cursor;
	}

	return this->tcp_context_list.end ();
}

std::list< struct tcp_context >::iterator TCPAssignment::find_pending_context (int num, std::list< struct tcp_context > *pending_conn_list)
{
	std::list< struct tcp_context >::iterator cursor;

	for (cursor = (*pending_conn_list).begin (); cursor != (*pending_conn_list).end (); cursor++)
	{
		if (cursor->seq_num == num)
			return cursor;
	}

	return (*pending_conn_list).end ();
}

void TCPAssignment::remove_tcp_context (int pid, int sockfd)
{
	std::list< struct tcp_context >::iterator cursor = this->tcp_context_list.begin ();

	while (cursor != this->tcp_context_list.end ())
	{
		if (cursor->pid == pid && cursor->sockfd == sockfd)
			cursor = this->tcp_context_list.erase (cursor);
		else
			cursor++;
	}

	return;
}

double TCPAssignment::get_timeout_interval (std::list< struct tcp_context >::iterator current_tcp_context)
{
	double estimatedRTT = current_tcp_context->estimatedRTT;
	double sampleRTT = current_tcp_context->sampleRTT;
	double devRTT = current_tcp_context->devRTT;
	double timeoutInterval;

	estimatedRTT = (1 - ALPHA) * estimatedRTT + ALPHA * sampleRTT;
	devRTT = (1 - BETA) * devRTT + BETA * abs (sampleRTT - estimatedRTT);
	timeoutInterval = estimatedRTT + 4 * devRTT;

	current_tcp_context->estimatedRTT = estimatedRTT;
	current_tcp_context->devRTT = devRTT;
	current_tcp_context->timeoutInterval = timeoutInterval;

	return timeoutInterval;
}

}
