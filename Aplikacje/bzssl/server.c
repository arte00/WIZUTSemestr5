#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
 
// #define SERVPORT 5003
#define BACKLOG 10
#define MAXDATASIZE 100 // maksymalna ilość dancyh, jaką możemy odebrać

void sigchld_handler(int s)
    {
        while(wait(NULL) > 0);
    }
 
int main(int argc, char *argv[])
{
   int sd, rc, port, new_sd;
   struct sockaddr_in serveraddr, clientaddr;
   int clientaddrlen = sizeof(clientaddr);
   int serveraddrlen = sizeof(serveraddr);
   struct sigaction sa;
   int yes=1;
   char buf[MAXDATASIZE];
   int numbytes;

   if (argc != 2) {
      fprintf(stderr,"usage: server port\n");
      exit(1);
   }

   if ((port = atoi(argv[1])) == 0)
   {
      perror("Bledny numer portu");
      exit(1);
   }

   if ((sd = socket(AF_INET, SOCK_STREAM, 0)) < 0)  
   {
      perror("blad funkcji socket():");
      exit(-1);
   }

   if (setsockopt(sd,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof(int)) == -1) 
   {
      perror("blad funkcji setsockopt():");
      exit(1);
   }

   memset(&serveraddr, 0x00, serveraddrlen);
   serveraddr.sin_family      = AF_INET;
   serveraddr.sin_port        = htons(port);
   serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);

   rc = bind(sd, (struct sockaddr *)&serveraddr, serveraddrlen); 
   if (rc< 0) 
   {
      perror("blad funkcji bind():");
      close(sd);
      exit(-1);
   }

   rc = listen(sd, BACKLOG); 
   if (rc==-1)
   {
      perror("blad funkcji listen():");
      exit(1);
   }

   sa.sa_handler = sigchld_handler;
   sigemptyset(&sa.sa_mask);
   sa.sa_flags = SA_RESTART;
   rc = sigaction(SIGCHLD, &sa, NULL);
   if (rc==-1)
   {
      perror("blad funkcji sigaction()");
      exit(1);
   }

   while(1) 
   {
      if ((new_sd = accept(sd, (struct sockaddr *) &clientaddr, &clientaddrlen)) == -1) 
      {
         perror("accept");
         continue;
      }

      printf("polaczono z: %s\n",inet_ntoa(clientaddr.sin_addr));
      if (!fork()) 
      {
         close(sd);
         if ((numbytes=recv(new_sd, buf, MAXDATASIZE-1, 0)) == -1) 
         {
            perror("recv");
            exit(1);
         }
         buf[numbytes] = '\0';
         printf("serwer tcp odebral: %s \n",buf);	
         close(new_sd);
         exit(0);
      }
      close(new_sd);
   }
   return (1);
}
