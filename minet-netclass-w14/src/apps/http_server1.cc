#include "minet_socket.h"
#include <stdlib.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/stat.h>

#define BUFSIZE 1024
#define FILENAMESIZE 100

int handle_connection(int);
int writenbytes(int,char *,int);
int readnbytes(int,char *,int);

int main(int argc,char *argv[])
{
  	int server_port;
  	int sock,sock2;
  	struct sockaddr_in sa,sa2;
  	int rc;

  	/* parse command line args */
  	if (argc != 3)
  	{
    		fprintf(stderr, "usage: http_server1 k|u port\n");
    		exit(-1);
  	}
  	server_port = atoi(argv[2]);
  	if (server_port < 1500)
  	{
    		fprintf(stderr,"INVALID PORT NUMBER: %d; can't be < 1500\n",server_port);
   		 exit(-1);
  	}

  	/* initialize and make socket */
  	if (toupper(*(argv[1]))=='K') 
    		minet_init(MINET_KERNEL);
  	else if (toupper(*(argv[1]))=='U') 
    		minet_init(MINET_USER);
  	else 
	{
    		fprintf(stderr, "Error: first argument must be k or u\n");
    		exit(-1);
  	}

  	if ((sock = minet_socket(SOCK_STREAM))<0)
  	{
    		minet_perror("Error: coud not make socket\n");
    		exit(-1);
  	}

  	/* set server address*/
  	memset(&sa, 0, sizeof sa);
  	sa.sin_port = htons(server_port);
 	sa.sin_addr.s_addr = htonl(INADDR_ANY);
  	sa.sin_family = AF_INET;

  	/* bind listening socket */
  	if ((rc = minet_bind(sock,&sa))<0)
  	{
    		minet_perror("Error: could not bind listening socket\n");
    		exit(-1);
  	}

  	/* start listening */
  	if ((rc = minet_listen(sock,5))<0)
  	{
    		minet_perror("Error: could not start listening\n");
    		exit(-1);
  	}

  	/* connection handling loop */
  	while(1)
  	{
    		if ((sock2 = minet_accept(sock,&sa2))<0)
    		{
      			minet_perror("Error: could not accept a connection ");
      			continue;
    		}
    		rc = handle_connection(sock2);
  	}
}

int handle_connection(int sock2)
{
  	char filename[FILENAMESIZE+1];
  	int rc = 0;
  	int fd;
  	struct stat filestat;
  	char buf[BUFSIZE+1];
  	char *bptr;
  	int datalen=0;
  	char *ok_response_f = "HTTP/1.0 200 OK\r\n"\
                      "Content-type: text/plain\r\n"\
                      "Content-length: %d \r\n\r\n";
  	char ok_response[100];
  	char *notok_response = "HTTP/1.0 404 FILE NOT FOUND\r\n"\
                         "Content-type: text/html\r\n\r\n"\
                         "<html><body bgColor=black text=white>\n"\
                         "<h2>404 FILE NOT FOUND</h2>\n"
                         "</body></html>\n";
  	bool ok=true;

  	/* first read loop -- get request and headers*/
        for (datalen = rc; (((rc=minet_read(sock2, buf+datalen, BUFSIZE-datalen))>0) && ((strstr(buf,"\r\n\r\n")) != NULL)); datalen += rc)
        {
                buf[rc+datalen] = '\0';
        }
        if (rc < 0)
        {
                minet_perror("Fail: could not read request\n");
                minet_close(sock2);
                return -1;
        }

  /* parse request to get file name */
  /* Assumption: this is a GET request and filename contains no spaces*/

	bptr = strtok(buf, " ");
        if (bptr != NULL)
        {
		bptr = strtok(NULL, " ");
                if (strlen(bptr) <= FILENAMESIZE)
                {
                        if (bptr[0] == '/')
                                strcpy(filename, bptr+1);
                        else
                                strcpy(filename, bptr);
        		
			/* try opening the file */	
			if ((fd = open(filename,O_RDONLY))<0)
     			{
				ok = false;
				fprintf(stderr,"Error: could not open file\n");
	        	}
		}
                else
                {
                       	fprintf(stderr,"Error: Filename is too big\n");
                       	minet_close(sock2);
                       	return -1;
               	}
        }
        else
        {
                ok = false;
        }



  	/* send response */
  	if (ok)
  	{
    		/* send headers */
    		if ((rc = stat(filename,&filestat))<0)
    		{
      			fprintf(stderr, "Error: could not get file stat\n");
     		 	minet_close(sock2);
      			return -1;
    		}

    		sprintf(ok_response,ok_response_f,filestat.st_size);
    		if ((rc = writenbytes(sock2,ok_response,strlen(ok_response)))<0)
    		{
      			minet_perror("Error: could not write response\n");
      			minet_close(sock2);
      			return -1;
    		}

    		/* send file */
    		while ((rc = read(fd,buf,BUFSIZE)) != 0)
    		{
	      		if (rc < 0)
      			{
				fprintf(stderr,"Error: could not read requested file %s\n",filename);
				break;
      			}
      			else
      			{
				if ((rc = writenbytes(sock2, buf, rc))<0)
        			{
					minet_perror("Error: could not write response\n");
					minet_close(sock2);
					return -1;
				}
	      		}
	    	}
	 }
	 else
  	{
    		if ((rc = writenbytes(sock2,notok_response,strlen(notok_response)))<0)
   		{
      			minet_perror("Error: could not  write response\n");
      			minet_close(sock2);
      			return -1;
    		}
  	}

  	//free(headers);
 	 minet_close(sock2);
  
 	 if (ok)
    		return 0;
  	else
    		return -1;
}

int readnbytes(int fd,char *buf,int size)
{
	  int rc = 0;
 	 int totalread = 0;
 	 while ((rc = minet_read(fd,buf+totalread,size-totalread)) > 0)
   		 totalread += rc;

  	if (rc < 0)
  	{
  	 	 return -1;
  	}
 	 else
    		return totalread;
}

int writenbytes(int fd,char *str,int size)
{
  	int rc = 0;
  	int totalwritten =0;
 	 while ((rc = minet_write(fd,str+totalwritten,size-totalwritten)) > 0)
    		totalwritten += rc;
  
  	if (rc < 0)
    		return -1;
  	else
    		return totalwritten;
}

