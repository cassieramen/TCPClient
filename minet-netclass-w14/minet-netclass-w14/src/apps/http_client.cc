#include "minet_socket.h"
#include <stdlib.h>
#include <ctype.h>

#define BUFSIZE 1024

int write_n_bytes(int fd, char * buf, int count);

int main(int argc, char * argv[]) {
    char * server_name = NULL;
    int server_port = 0;
    char * server_path = NULL;

    int sock = 0;
    int rc = -1;
    int datalen = 0;
    bool ok = true;
    struct sockaddr_in sa;
    FILE * wheretoprint = stdout;
    struct hostent * site = NULL;
    char * req = NULL;

    char buf[BUFSIZE + 1];
    char * bptr = NULL;
    char * bptr2 = NULL;
    char * endheaders = NULL;
   
    struct timeval timeout;
    fd_set set;

    /*parse args */
    if (argc != 5) {
	fprintf(stderr, "usage: http_client k|u server port path\n");
	exit(-1);
    }

    server_name = argv[2];
    server_port = atoi(argv[3]);
    server_path = argv[4];



    /* initialize minet */
    if (toupper(*(argv[1])) == 'K') { 
	minet_init(MINET_KERNEL);
    } else if (toupper(*(argv[1])) == 'U') { 
	minet_init(MINET_USER);
    } else {
	fprintf(stderr, "First argument must be k or u\n");
	exit(-1);
    }

    /* create socket */
    sock = socket(AF_INET,SOCK_STREAM,0);
    if (sock<0) { //the socket couldn't be created
        minet_perror("Could not create the socket");
	exit(-1);
    }

    // Do DNS lookup
    /* Hint: use gethostbyname() */
    site = gethostbyname(server_name);

    /* set address sockaddr_in struct has fields:
 *   short sin_family
 *   unsigned short sin_port
 *   IN_ADDR sin_addr
 *   char sin_zero[8] |||||| this is just padding*/
    sa.sin_family = AF_INET;
    sa.sin_port = htons(server_port);
    bcopy((char*) site->h_addr, (char*)  &sa.sin_addr.s_addr, site->h_length);

    /* connect socket */
    int connection = minet_connect(sock, (struct sockaddr_in *) &sa);
    if (connection != 0) {
        minet_perror("Could not connect");
        minet_close(sock);
        exit(-1);
    }

    /* send request */
    req = (char *) malloc(15 + strlen(server_path));
    sprintf(req, "GET %s HTTP/1.0\n\n",server_path);
    int write = minet_write(sock, req, strlen(req));
    if (write<0) {
       minet_perror("HTTP GET request failed");
       minet_close(sock);
       exit(-1);
    }

    /* wait till socket can be read */
    /* Hint: use select(), and ignore timeout for now. */
    FD_ZERO(&set);
    FD_SET(sock, &set);

    if(FD_ISSET(sock, &set) == 0) {
        minet_perror("Socket not added");
        minet_close(sock);
        exit(-1);
    }

    if(minet_select(sock+1, &set, 0, 0, 0) < 0) {
       minet_perror("Socket not ready");
       minet_close(sock);
       exit(-1);
    } 
 
    /* first read loop -- read headers */
    
    /* examine return code */   
    //Skip "HTTP/1.0"
    //remove the '\0'
    // Normal reply has return code 200
    int read = minet_read(sock ,buf, BUFSIZE);
    if (read<0) {
        minet_perror("Could not decode response");
        minet_close(sock);
        exit(-1);
    }
    sscanf(buf, "%*s %d", &rc);
    if (rc !=200) {
        ok = false;
    }

    /* print first part of response */

    /* second read loop -- print out the rest of the response */
    
    /*close socket and deinitialize */

    fprintf(wheretoprint, "Request status is: %d\n", rc);
    
    char *response = buf;
    while(!(response[0] == '\n' && response[-2] == '\n')) {
         response++;
    }

    if (ok) {
        fprintf(wheretoprint, response);
        while((datalen=minet_read(sock,buf,BUFSIZE)) > 0) {
             buf[datalen] = '\0';
             fprintf(wheretoprint,"%s",buf);
        }
        minet_close(sock);
        minet_deinit();
	return 0;
    } else {
        minet_close(sock);
        minet_deinit();
	return -1;
    }
}

int write_n_bytes(int fd, char * buf, int count) {
    int rc = 0;
    int totalwritten = 0;

    while ((rc = minet_write(fd, buf + totalwritten, count - totalwritten)) > 0) {
	totalwritten += rc;
    }
    
    if (rc < 0) {
	return -1;
    } else {
	return totalwritten;
    }
}


