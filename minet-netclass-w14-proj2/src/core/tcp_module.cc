#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>


#include <iostream>

#include "Minet.h"
#include "packet.h"
#include "buffer.h"
#include "ip.h"
#include "tcp.h"
#include "sockint.h"
#include "tcpstate.h"

using std::cout;
using std::endl;
using std::cerr;
using std::string;

void constructPacket(Packet& packet, ConnectionToStateMapping<TCPState>& connectionState,int dataSize, int flag);

int main(int argc, char *argv[])
{
  MinetHandle mux, sock;
  ConnectionList<TCPState> clist;

  MinetInit(MINET_TCP_MODULE);

  mux=MinetIsModuleInConfig(MINET_IP_MUX) ? MinetConnect(MINET_IP_MUX) : MINET_NOHANDLE;
  sock=MinetIsModuleInConfig(MINET_SOCK_MODULE) ? MinetAccept(MINET_SOCK_MODULE) : MINET_NOHANDLE;

  if (MinetIsModuleInConfig(MINET_IP_MUX) && mux==MINET_NOHANDLE) {
    MinetSendToMonitor(MinetMonitoringEvent("Can't connect to mux"));
    return -1;
  }

  cout << "tcp_module handling tcp traffic ........... \n";

  if (MinetIsModuleInConfig(MINET_SOCK_MODULE) && sock==MINET_NOHANDLE) {
    MinetSendToMonitor(MinetMonitoringEvent("Can't accept from sock module"));
    return -1;
  }

  MinetSendToMonitor(MinetMonitoringEvent("tcp_module handling TCP traffic"));

  MinetEvent event;

  while (MinetGetNextEvent(event)==0) {
    // if we received an unexpected type of event, print error
    if (event.eventtype!=MinetEvent::Dataflow 
	|| event.direction!=MinetEvent::IN) {
      MinetSendToMonitor(MinetMonitoringEvent("Unknown event ignored."));
    // if we received a valid event from Minet, do processing
    } else {
      //  Data from the IP layer below  //
      if (event.handle==mux) {
	Packet p;
	MinetReceive(mux,p);
	unsigned tcphlen=TCPHeader::EstimateTCPHeaderLength(p);
	cerr << "estimated header len="<<tcphlen<<"\n";
	p.ExtractHeaderFromPayload<TCPHeader>(tcphlen);
	IPHeader ipl=p.FindHeader(Headers::IPHeader);
	TCPHeader tcph=p.FindHeader(Headers::TCPHeader);

	cerr << "TCP Packet: IP Header is "<<ipl<<" and ";
	cerr << "TCP Header is "<<tcph << " and ";

	cerr << "Checksum is " << (tcph.IsCorrectChecksum(p) ? "VALID" : "INVALID");
	
      }
      //  Data from the Sockets layer above  //
      if (event.handle==sock) {
	SockRequestResponse s;
	MinetReceive(sock,s);

	ConnectionList<TCPState>::iterator cs = clist.FindMatching(s.connection);

	cout << "Received Socket Request:" << s << endl;

	switch(s.type) {
	case CONNECT: {
		cout << "Inside connect statement" << endl;
		//start the 3 way handshake - active open
		Packet synPacket;
		
		int timerTries = 3;
		//create TCB/send syn
		TCPState tcpState = TCPState(1, SYN_SENT, timerTries);
		ConnectionToStateMapping<TCPState> connectionState;
		connectionState.connection = s.connection;
		connectionState.timeout = Time();
		connectionState.state = tcpState;
		connectionState.bTmrActive =  false;
		//let's increment how many we've tried
		connectionState.state.SetLastSent(connectionState.state.GetLastSent()+1);
		
		//now we have connection status so let's put it into a packet
		unsigned char syn = 0;
		SET_SYN(syn); 
		constructPacket(synPacket, connectionState, 0, syn);
		MinetSend(mux,synPacket);
		sleep(2);
		MinetSend(mux,synPacket);	

		clist.push_front(connectionState);

		//Let the socket know we're happy
		SockRequestResponse resp;
		resp.type = STATUS;
		resp.error = EOK;
		resp.bytes = 0;
		resp.connection = s.connection;
		MinetSend(sock, resp);

		break;
	}
	case ACCEPT: {
		//Passive open,(or close)  we just want to listen
		cout << "Inside accept statement" << endl;
		
		unsigned int state = (*cs).state.GetState();
	
		if (state!= FIN_WAIT1) {
			unsigned int timerTries = 3;
			TCPState tcpState = TCPState(rand(), LISTEN, timerTries);
			
			ConnectionToStateMapping<TCPState> connectionState;
			connectionState.connection = s.connection;
			connectionState.state = tcpState;
			//Don't send out a packet as per the FSM

			clist.push_front(connectionState);

			//Socket reply
			SockRequestResponse resp;
			resp.type = STATUS;
			resp.bytes = 0;
			resp.error = EOK;
			MinetSend(sock,resp);
		}
		break;
	}
	case STATUS: {
		cout << "Inside status statment" << endl;
		//ignored? sure. 
		break;
	}
	case WRITE: {
		cout << "Inside write statement" << endl; 
		unsigned int state = (*cs).state.GetState();

		//we shouldn't be writing unless we have a connection established
		if (state == ESTABLISHED) {
			//the data is the max size - (two headers)
			unsigned dataSize = MIN_MACRO(IP_PACKET_MAX_LENGTH-IP_HEADER_BASE_LENGTH-TCP_HEADER_BASE_LENGTH,s.data.GetSize());
			//from buffer.h
			Packet packet = Packet(s.data.ExtractFront(dataSize));
			unsigned char ack = 0;
			SET_ACK(ack);
			constructPacket(packet,*cs, dataSize, ack);
			MinetSend(mux, packet);

			//as always, send info to our socket
			SockRequestResponse resp;
			resp.type = STATUS;
			resp.bytes = dataSize;
			resp.error = EOK;
			resp.connection = s.connection;
			MinetSend(sock, resp);
		}


		break;
	}
	case FORWARD: {
		cout << "Inside forward statement" << endl; 
		SockRequestResponse resp;
		resp.type = STATUS;
		resp.error = EOK;
		resp.bytes = 0;
		MinetSend(sock,resp);

		break;
	}
	case CLOSE: {
	//FIN stuff. Need to send ack, recieve ack, send fin
		cout << "Inside close statement" << endl;
		break;
	}
	default: {
	}
	}
      }
    }
  }
  return 0;
}


void constructPacket(Packet& packet, ConnectionToStateMapping<TCPState>& connectionState,int dataSize, int flag) {
	unsigned char flags = 0;
	int packetSize = dataSize + TCP_HEADER_BASE_LENGTH + IP_HEADER_BASE_LENGTH;

	IPHeader ipHeader;
	IPAddress source = connectionState.connection.src;
	IPAddress dest = connectionState.connection.dest;
	//configure the ip header - from ip.h	
	ipHeader.SetSourceIP(source);
	ipHeader.SetDestIP(dest);
	ipHeader.SetTotalLength(packetSize);
	ipHeader.SetProtocol(IP_PROTO_TCP);
	//add it to the packet
	packet.PushFrontHeader(ipHeader);

	if (IS_URG(flag)) {
		SET_URG(flags);
	} else if (IS_RST(flag)) {
		SET_RST(flags);
	} else if (IS_ACK(flag)) {
		SET_ACK(flags);
	} else if (IS_FIN(flag)) {
		SET_FIN(flags);
	} else if (IS_SYN(flag)) {
		SET_SYN(flags);
	} else if (IS_PSH(flag)) {
		SET_PSH(flags);
	}

	TCPHeader tcpHeader;
	//configure the tcp header - from tcp.h
	tcpHeader.SetSourcePort(connectionState.connection.srcport, packet);
	tcpHeader.SetDestPort(connectionState.connection.destport, packet);
	tcpHeader.SetSeqNum(connectionState.state.GetLastSent(),packet);
	tcpHeader.SetAckNum(connectionState.state.GetLastRecvd()+1,packet);
	tcpHeader.SetHeaderLen(TCP_HEADER_BASE_LENGTH/4,packet);
	tcpHeader.SetFlags(flags,packet);
	tcpHeader.SetWinSize(connectionState.state.GetN(),packet);
	tcpHeader.RecomputeChecksum(packet);
	tcpHeader.SetUrgentPtr(0,packet);
	//add the tcp  header
	packet.PushBackHeader(tcpHeader);

}
