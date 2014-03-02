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


#include <iostream>\

#define SEND_ACK 0
#define SEND_S_ACK 1
#define SEND_S 2
#define SEND_F 3
#define SEND_RST 4

#include "Minet.h"
#include "packet.h"
#include "buffer.h"
#include "ip.h"
#include "tcp.h"
#include "sockint.h"
#include "tcpstate.h"

using std::cerr;
using std::cout;
using std::endl;
using std::cerr;
using std::string;

void constructPacket(Packet& packet, ConnectionToStateMapping<TCPState>& connectionState,int dataSize, int flag);
void HandleMux(const MinetHandle &mux, const MinetHandle &sock, ConnectionList<TCPState> &clist);
void debug_output(ConnectionList<TCPState>::iterator cs, unsigned char flags, unsigned int seqnum, unsigned int acknum);

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

  cerr << "tcp_module handling tcp traffic ........... \n";

  if (MinetIsModuleInConfig(MINET_SOCK_MODULE) && sock==MINET_NOHANDLE) {
    MinetSendToMonitor(MinetMonitoringEvent("Can't accept from sock module"));
    return -1;
  }

  MinetSendToMonitor(MinetMonitoringEvent("tcp_module handling TCP traffic"));

  MinetEvent event;
  double timeout = -1;
  while (MinetGetNextEvent(event,timeout)==0) {
    // if we received an unexpected type of event, print error
    if (event.eventtype!=MinetEvent::Dataflow || event.direction!=MinetEvent::IN) {
      	MinetSendToMonitor(MinetMonitoringEvent("Unknown event ignored."));
    	// if we received a valid event from Minet, do processing
    	if (event.eventtype==MinetEvent::Timeout)
    	{
	  cerr << "Timeout event....... \n";
	
	  SockRequestResponse resp;
	  MinetReceive(sock, resp);
	  ConnectionList<TCPState>::iterator cs = clist.FindMatching(resp.connection);
	  if(cs != clist.end()) {
	    if(Time().operator > ((*cs).timeout)) {
	      unsigned int state = (*cs).state.GetState();
	      if (state == SYN_SENT || state == TIME_WAIT || (*cs).state.ExpireTimerTries()) {
		cerr << "CLOSING THIS CONNECTION WOOO!" << endl;
		clist.erase(cs);	
	      } else if (state == ESTABLISHED) {
		(*cs).timeout = Time() + 50; //give it extra
		ConnectionToStateMapping<TCPState>& connectionState = (*cs);
		int bufferLen = connectionState.state.SendBuffer.GetSize(); //what's in there now
		
		char buffer[TCP_MAXIMUM_SEGMENT_SIZE];
		int bufferPlaceHolder = 0;

		while( bufferLen > 0) {
		  int data = connectionState.state.SendBuffer.GetData(buffer,TCP_MAXIMUM_SEGMENT_SIZE,bufferPlaceHolder);
		  Packet packet = Packet(buffer, data);

		  constructPacket(packet,*cs, data, 0);
		  TCPHeader tcph = packet.FindHeader(Headers::TCPHeader);
		  tcph.SetSeqNum(connectionState.state.GetLastSent() + bufferPlaceHolder + data, packet);
		  packet.PushBackHeader(tcph);

		  MinetSend(mux, packet);
		  bufferPlaceHolder += TCP_MAXIMUM_SEGMENT_SIZE;
 		  bufferLen -= TCP_MAXIMUM_SEGMENT_SIZE;
		}

	      }
	    }
	  } 
    	} 
   } else {
      //  Data from the IP layer below  //
      
      if (event.handle==mux) {
	HandleMux(mux, sock, clist);

      }
      //  Data from the Sockets layer above  //
      if (event.handle==sock) {
	cerr << "We are in sock handler\n";
	SockRequestResponse s;
	MinetReceive(sock,s);

	ConnectionList<TCPState>::iterator cs = clist.FindMatching(s.connection);

	cerr << "Received Socket Request:\n\n" << s << endl;

	switch(s.type) {
	case CONNECT: {
		cerr << "Inside connect statement" << endl;
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
		cerr << "Inside accept statement" << endl;
		
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
		cerr << "Inside status statment" << endl;
		//ignored? sure. 
		break;
	}
	case WRITE: {
		cerr << "Inside write statement" << endl; 
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
		cerr << "Inside forward statement" << endl; 
		SockRequestResponse resp;
		resp.type = STATUS;
		resp.error = EOK;
		resp.bytes = 0;
		MinetSend(sock,resp);

		break;
	}
	case CLOSE: {
	//FIN stuff. Need to send ack, recieve ack, send fin
		cerr << "Inside close statement" << endl;
		unsigned int state = (*cs).state.GetState();

		switch(state) {
		case SYN_SENT: {
		//we sent out our syn, should be wrapped up
			clist.erase(cs);
		} break;
		case SYN_RCVD: {
			Packet packet;
			unsigned char fin = 0;
			SET_FIN(fin);
			constructPacket(packet, *cs, 0,fin);
			MinetSend(mux,packet);
				
			(*cs).state.SetLastSent((*cs).state.GetLastSent()+1); 
			(*cs).state.SetState(FIN_WAIT1);
		} break;
		}

	}
	default: {
	}
	}
      }
    }
  }

  ConnectionList<TCPState>::iterator first = clist.FindEarliest();
  timeout = Time() - (*first).timeout;
  return 0;
}



void HandleMux(const MinetHandle &mux, const MinetHandle &sock, ConnectionList<TCPState> &clist) {

	cerr << "Recieved a MUX event \n\n";
	Packet p;
	unsigned short totalLength, dataLength;
	unsigned char ipHeaderLength;
	
	
	//get the packet
	MinetReceive(mux,p);
	
	//get the header length estimate
	unsigned tcphlen=TCPHeader::EstimateTCPHeaderLength(p);
//	cerr << "estimated header len="<<tcphlen<<"\n";
	
	//extract headers
	p.ExtractHeaderFromPayload<TCPHeader>(tcphlen);
	IPHeader ipl=p.FindHeader(Headers::IPHeader);
	TCPHeader tcph=p.FindHeader(Headers::TCPHeader);

	// check checksum
	bool checkSum = tcph.IsCorrectChecksum(p);
	
	//output relevant info
//	cerr << "TCP Packet: IP Header is "<<ipl<<" and ";
//	cerr << "TCP Header is "<<tcph << " and ";
//	cerr << "Checksum is " << (checkSum ? "VALID" : "INVALID");
	

	//let's get all the info for the ipheader and tcpheader
	//functionss in tcp.h and ip.h

	//new connection object
	Connection connection; //put it all here

	ipl.GetProtocol(connection.protocol);
	ipl.GetSourceIP(connection.dest);
	ipl.GetDestIP(connection.src);	
	

	unsigned int seqNum, ackNum;
	unsigned char flags;
	unsigned short winSize;
	
	tcph.GetSourcePort(connection.destport);
	tcph.GetDestPort(connection.srcport);
	tcph.GetSeqNum(seqNum);
	tcph.GetAckNum(ackNum);
	tcph.GetFlags(flags);
	tcph.GetWinSize(winSize);

	//now locate the connection using our handy clist
	ConnectionList<TCPState>::iterator c_list = clist.FindMatching(connection);
	
//	cerr << "\nWe think we found the connection " << connection << "\n" << endl;
//	cerr << "Client List size is " << clist.size() << "\n" << endl;
	
	//cerr << "c_list : " << c_list << " clist.end: " << clist.end() <<"\n"<<endl;
	if(c_list!=clist.end()) {
	        Packet pToSend;
		SockRequestResponse sockRq, sockRp;
	        ipl.GetTotalLength(totalLength);
	        ipl.GetHeaderLength(ipHeaderLength);
	        dataLength = totalLength - ipHeaderLength - tcphlen;
//	        cerr << "\n Total data length is " << dataLength << endl;
	  
	        Buffer data = p.GetPayload().ExtractFront(dataLength);
		unsigned int state = (*c_list).state.GetState();
		(*c_list).state.rwnd = winSize;
		
		cerr <<"BEGINING OF SWITCH STATEMENTS\n";
		switch(state) {
		   case CLOSED:
		     cerr <<"WE ARE CLOSED\n\n";
		     break;
		   case LISTEN:
		     cerr << "WE ARE LISTENING \n\n";
		  
		     if (IS_SYN(flags)){
		       //set the connection first
		       (*c_list).connection = connection;
				
		       //update all states now
		       (*c_list).state.SetState(SYN_RCVD); //set the state to syn_rcvd if the syn bit is set
		       (*c_list).state.SetLastRecvd(seqNum);
		       (*c_list).state.SetSendRwnd(winSize);
		       (*c_list).state.SetLastSent(90);
		       (*c_list).state.SetLastAcked(90);
			 debug_output(c_list, flags, seqNum, ackNum);
		       //deal with timer stuff
		       (*c_list).bTmrActive = true;
		       (*c_list).timeout = Time()+ 30;
			
			unsigned char syn_ack = 0;	
			SET_SYN(syn_ack);
      			SET_ACK(syn_ack);
		       constructPacket(pToSend,*c_list, 0,syn_ack);
		       MinetSend(mux, pToSend);
			
			(*c_list).state.SetLastSent((*c_list).state.GetLastSent()+1); 
			tcph.GetAckNum(ackNum);	 
		       }
		      
		     break;
		   case SYN_RCVD:
			 cerr << "We are in SYN_RCVD!!\n";
			  
			  debug_output(c_list, flags, seqNum, ackNum);
			if (IS_ACK(flags) && ((*c_list).state.GetLastRecvd()+1 == seqNum))
			{
				printf("Established\n");
				(*c_list).state.SetState(ESTABLISHED);
				(*c_list).state.SetSendRwnd(winSize);
				(*c_list).state.SetLastAcked((*c_list).state.GetLastAcked()+1);
				(*c_list).bTmrActive = false;

				sockRp.type = WRITE;
				sockRp.connection = connection; 
				sockRp.error = EOK; 
				sockRp.bytes = 0;
				MinetSend(sock, sockRp);
				  
			}
				
		     break;
		   case SYN_SENT:
			if (IS_SYN(flags) && IS_ACK(flags) && ((*c_list).state.GetLastSent() + 1 == ackNum))
			{
				cerr <<"WE ARE IN SYN SENT\n";
				cerr << "Getlastsent + 1 == acknum\n";
				(*c_list).state.SetState(ESTABLISHED);
				(*c_list).state.SetSendRwnd(winSize);
				(*c_list).state.SetLastAcked(ackNum);
				(*c_list).state.SetLastRecvd(seqNum);
				unsigned char setAck = 0;
				 SET_ACK(setAck);
				constructPacket(pToSend, *c_list, 0, setAck);
				MinetSend(mux, pToSend);
				
					sockRp.type = WRITE;
					sockRp.connection = connection;
					sockRp.error=EOK;
					sockRp.bytes=0;
					MinetSend(sock,sockRp);
				   
			}
		     break;
		   case ESTABLISHED:
			
			
		     break;
		   case CLOSE_WAIT:
		     break;
		   case FIN_WAIT1:
		     break;
		   case CLOSING:
		     break;
		   case LAST_ACK:
		     break;
		   case TIME_WAIT:
		     break;

		}

	}


}

void constructPacket(Packet& packet, ConnectionToStateMapping<TCPState>& connectionState,int dataSize, int flag) {
	
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


	TCPHeader tcpHeader;
	//configure the tcp header - from tcp.h
	tcpHeader.SetSourcePort(connectionState.connection.srcport, packet);
	tcpHeader.SetDestPort(connectionState.connection.destport, packet);
	tcpHeader.SetSeqNum(connectionState.state.GetLastSent(),packet);
	tcpHeader.SetAckNum(connectionState.state.GetLastRecvd()+1,packet);
	tcpHeader.SetHeaderLen(TCP_HEADER_BASE_LENGTH/4,packet);
	tcpHeader.SetFlags(flag,packet);
	tcpHeader.SetWinSize(connectionState.state.GetN(),packet);
	tcpHeader.RecomputeChecksum(packet);
	tcpHeader.SetUrgentPtr(0,packet);
	unsigned int ackTemp;
	tcpHeader.GetAckNum(ackTemp);
	//add the tcp  header
	cout<<"------ We are sending out a packet! -----"<<endl;
  	cout<<"AckNum being sent out: "<<connectionState.state.GetLastRecvd()+1<<endl;
 	 cout<<"SeqNum being sent out: "<<connectionState.state.GetLastSent()<<endl;
	cout<<"AckNum being sent out: "<<ackTemp<<endl;  
	  cout<<"-----------------------------------------"<<endl;
	packet.PushBackHeader(tcpHeader);

	

}

void debug_output(ConnectionList<TCPState>::iterator cs, unsigned char flags, unsigned int seqnum, unsigned int acknum){
  cout<<"----------------------------"<<endl;
  cout<<"Just received seqnum: "<<seqnum<<endl;
  cout<<"Just received acknum: "<<acknum<<endl;
  cout<<"State: "<<(*cs).state.GetState()<<endl;
  cout<<"LastRecvd: "<<(*cs).state.GetLastRecvd()<<endl;
  cout<<"LastSent: "<<(*cs).state.GetLastSent()<<endl;
  cout<<"LastAcked: "<<(*cs).state.GetLastAcked()<<endl;
  printf("Flags: %d \n", flags);
  cout<<"----------------------------"<<endl;
}
