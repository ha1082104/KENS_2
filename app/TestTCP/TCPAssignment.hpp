/*
 * E_TCPAssignment.hpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: 근홍
 */

#ifndef E_TCPASSIGNMENT_HPP_
#define E_TCPASSIGNMENT_HPP_


#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_RoutingInfo.hpp>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <list>
#include <E/Networking/E_Packet.hpp>

#include <E/E_TimerModule.hpp>

namespace E
{
	enum TCP_STATE
	{
		CLOSED,
		LISTEN,
		SYN_RCVD,
		SYN_SENT,
		ESTABLISHED,
		CLOSE_WAIT,
		FIN_WAIT_1,
		FIN_WAIT_2,
		CLOSING,
		TIME_WAIT,
		LAST_ACK
	};

	struct wakeup_arguments
	{
		UUID syscallUUID;
		struct sockaddr *addr;
		socklen_t *addrlen;

		/* for read call */
		void *buffer;
		int length;
	};

	struct timer_arguments
	{
		int pid;
		int sockfd;
		unsigned int seq_num;
	};

	struct tcp_context
	{
		TCP_STATE tcp_state = CLOSED;
		int pid;
		int sockfd;
		unsigned int src_addr;
		unsigned int dst_addr;
		unsigned short src_port;
		unsigned short dst_port;
		bool is_bound = false;
	    int backlog;
		unsigned int seq_num;
		unsigned int ack_num;
		int fin_num;
		int to_be_accepted = 0;
		std::list< struct tcp_context > pending_conn_list;
		std::list< struct tcp_context > estab_conn_list;
		struct wakeup_arguments wake_args;

		/* for transfer */
		std::list< struct sent_packet > send_buffer;
		std::list< struct recv_packet > recv_buffer;
		unsigned short peer_window;
		double estimatedRTT = 100;
		double sampleRTT = 100;
		double devRTT = 0;
		double timeoutInterval = 0;
		double timeVar = 100;
		UUID transfer_timerUUID;
		UUID transfer_writeUUID;
		bool is_read_call = false;
		bool is_write_call= false;
	};

	struct tcp_header
	{
		unsigned short src_port;
		unsigned short dst_port;
		int seq_num;
		int ack_num;
		uint8_t hdr_len;
		uint8_t flags;
		unsigned short recv_window;
		unsigned short checksum;
		unsigned short urg_ptr;
	};

	struct sent_packet
	{
		Packet *packet;
		uint32_t sent_seq = 0;
		uint32_t expect_ack = 0;
		bool acked = false;
		int data_start = 0;
		int data_length = 0;
		double sent_time;
	};

	struct recv_packet
	{
		Packet *packet;
		unsigned int recv_seq = 0;
		int data_length = 0;
		int data_position = 0;				// 0 <= data_position <= data_length
	};

class TCPAssignment : public HostModule, public NetworkModule, public SystemCallInterface, private NetworkLog, private TimerModule
{
private:
	std::list < struct tcp_context > tcp_context_list;
	int random_seq_num = 0;
	unsigned short random_port = 10000;

	/* for trnasfer */
	uint32_t window_send_size = 5;
	int MSS = 512;

private:
	virtual void timerCallback(void* payload) final;

	/* System Call */
	void syscall_socket (UUID, int, int, int);
	void syscall_close (UUID, int, int);
	void syscall_read (UUID, int, int, void *, int);
	void syscall_write (UUID, int, int, const void *, int);
	void syscall_connect (UUID, int, int, struct sockaddr *, socklen_t addrlen);
	void syscall_listen (UUID, int, int, int);
	void syscall_accept (UUID, int, int, struct sockaddr *, socklen_t *);
	void syscall_bind (UUID, int, int, struct sockaddr *, socklen_t);
	void syscall_getsockname (UUID, int, int, struct sockaddr *, socklen_t *);
	void syscall_getpeername (UUID, int, int, struct sockaddr *, socklen_t *);
	std::list< struct tcp_context >::iterator find_tcp_context (int, int);
	unsigned short calculate_checksum (unsigned int, unsigned int, struct tcp_header, unsigned short *, int);
	std::list< struct tcp_context >::iterator get_context_addr_port (unsigned int, unsigned int, unsigned short, unsigned short);
	std::list< struct tcp_context >::iterator find_pending_context (int, std::list< struct tcp_context > *);
	void remove_tcp_context (int, int);
	bool insert_sent_packet (struct sent_packet **, struct sent_packet *);
	double get_timeout_interval (std::list< struct tcp_context >::iterator);

	void remove_acked_packet (std::list< struct sent_packet >*);
	void check_acked_packet (std::list< struct sent_packet >*, unsigned int);
	int unacked_data (std::list< struct sent_packet >);
	
	void insert_recv_packet (std::list< struct recv_packet > *, struct recv_packet);
	int remain_window_size (std::list< struct recv_packet >);
	int total_data_in_buffer (std::list< struct recv_packet >);
	int find_index (std::list< struct recv_packet >, int);

public:
	TCPAssignment(Host* host);
	virtual void initialize();
	virtual void finalize();
	virtual ~TCPAssignment();
protected:
	virtual void systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param) final;
	virtual void packetArrived(std::string fromModule, Packet* packet) final;
};

class TCPAssignmentProvider
{
private:
	TCPAssignmentProvider() {}
	~TCPAssignmentProvider() {}
public:
	static HostModule* allocate(Host* host) { return new TCPAssignment(host); }
};

}


#endif /* E_TCPASSIGNMENT_HPP_ */
