    #include <stdio.h>
    #include <stdlib.h>
    #include <unistd.h>
    #include <errno.h>
    #include <string.h>
    #include <netdb.h>
    #include <sys/types.h>
    #include <netinet/in.h>
    #include <sys/socket.h>

//    #define PORT 5003 // port, z ktorym klient bedzie sie laczyl

    #define MAXDATASIZE 100 // maksymalna ilosc dancyh, ktore mozemy wyslac

    int main(int argc, char *argv[])
    {
        int sockfd, numbytes;
        unsigned int port;             // port, z którym klient bedzie sie laczyc
        char msg[MAXDATASIZE];
        struct sockaddr_in their_addr; // informacja o adresie osoby laczacej sie
        struct hostent *he;

        if (argc != 3) {
            fprintf(stderr,"usage: client IP port\n");
            exit(1);
        }

        if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
            perror("socket");
            exit(1);
        }

        if ((port = atoi(argv[2])) == 0)
        {
            perror("Bledny numer portu");
            exit(1);
        }

        their_addr.sin_family = AF_INET;    // host byte order
        their_addr.sin_port = htons(port);  // short, network byte order
        their_addr.sin_addr.s_addr = inet_addr((const char*)argv[1]);

        memset(&(their_addr.sin_zero), '\0', 8);  // wyzeruj reszte struktury

        if (connect(sockfd, (struct sockaddr *)&their_addr, sizeof(struct sockaddr)) == -1) {
            perror("Nawiazanie polaczenia nie powiodlo sie!\n");
            exit(1);
        }

        printf("Polaczenie nawiazane\n");
        fflush(stdout);

	printf("Podaj tekst do wyslania: ");
	scanf("%[^\n]", msg);

	int wyslano;
	if ((wyslano = send(sockfd,msg,strlen(msg), 0)) == -1) {
            perror("send");
	}

	printf("Wyslano %i bajtow \n", wyslano);
        close(sockfd);

        return 0;
    }

