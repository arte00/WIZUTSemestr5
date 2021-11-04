#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <memory.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

// Pliki naglowkowe openssl
#include <openssl/rsa.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

// Zdefiniowanie polozenia certyfikatu oraz klucza
#define CERTF "clientcert.pem"
#define KEYF "clientkey.pem"
#define CAFILE "cacert.pem"
#define CADIR NULL

#define CHK_NULL(x) if((x)==NULL) exit (1)
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }

int verify_callback(int ok, X509_STORE_CTX *store)
{
    char data[256];
    if (!ok)
    {
        X509 *cert = X509_STORE_CTX_get_current_cert(store);
        int depth = X509_STORE_CTX_get_error_depth(store);
        int err = X509_STORE_CTX_get_error(store);
        fprintf(stderr, "-Error with certificate at depth: %i\n",depth);
        X509_NAME_oneline(X509_get_issuer_name(cert), data, 256);
        fprintf(stderr, " issuer     = %s\n", data);
        X509_NAME_oneline(X509_get_subject_name(cert), data, 256);
        fprintf(stderr, " subject = %s\n", data);
        fprintf(stderr, " err %i:%s\n", err,X509_verify_cert_error_string(err));
    }
    return ok;
}

int main(int argc, char *argv[])
{
    int err;
    int sd;
    struct sockaddr_in sa;
    SSL_CTX *ctx;
    SSL *ssl;
    X509 *server_cert;
    char *str;
    char buf[4096], msg[4096];
    const SSL_METHOD *meth;
    unsigned int port;             // port, z którym klient bedzie sie laczyc

    if (argc != 3) {
       fprintf(stderr,"usage: client IP port\n");
       exit(1);
    }

    if ((port = atoi(argv[2])) == 0)
    {
       perror("Bledny numer portu");
       exit(1);
    }

    // Tu inicjujemy ssl
    SSLeay_add_ssl_algorithms();
    meth = SSLv23_client_method();
    SSL_load_error_strings();

    // Tu tworzymy ctx
    ctx = SSL_CTX_new(meth);

    CHK_NULL(ctx);
    CHK_SSL(err);

     //- tu ustawiamy zaufanie do CA
   if (SSL_CTX_load_verify_locations(ctx, CAFILE, CADIR) != 1)
   {
        ERR_print_errors_fp(stderr);
        exit(6);
   }

     // tu ustawiamy plik certyfikatu
    if (SSL_CTX_use_certificate_file(ctx, CERTF, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        exit(3);
    }
    // tu ustawiamy plik klucza
    if( SSL_CTX_use_PrivateKey_file(ctx,KEYF, SSL_FILETYPE_PEM) <=0 )
    {
        ERR_print_errors_fp(stderr);
        exit(4);
    }

    // sprawdzamy poporawnosc klucza
    if( !SSL_CTX_check_private_key(ctx))
    {
        fprintf( stderr, "Nieprawidlowy klucz prywatny\n");
        exit(5);
    }

    // zadanie i sprawdzenie certyfiaktu serwera - jezeli sie
    // nie powiedzie to polaczenie jest przerywane
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);

    // ustawienie maxymalnej hierarchi do 4 poziomow
    SSL_CTX_set_verify_depth(ctx, 4);

    // Przygotowanie TCP
    sd = socket (AF_INET, SOCK_STREAM, 0);
    CHK_ERR(sd, "socket");

    memset( &sa, '\0', sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = inet_addr ((const char*)argv[1]);
    sa.sin_port = htons(port);
    err = connect(sd, (struct sockaddr*) &sa, sizeof(sa));
    CHK_ERR(err, "connect");

    // Tu tworzymy obiekt ssl
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sd);

    // Tu laczymy ssl
    err = SSL_connect(ssl);

    printf( "polaczenie SSL uzywa %s\n", SSL_get_cipher (ssl) );

    // Pobieramy certyfikat serwera
    server_cert = SSL_get_peer_certificate(ssl);
    printf("Certyfikat serwera:\n");
    str = X509_NAME_oneline (X509_get_subject_name (server_cert), 0, 0);
    printf("\t temat: %s\n", str);
    free(str);
    str = X509_NAME_oneline( X509_get_issuer_name(server_cert), 0, 0);
    printf("Wydany przez: %s\n", str);
    free(str);
    X509_free(server_cert);


    printf("\nPodaj komunikat: ");
    scanf("%[^\n]", msg);
    err = SSL_write(ssl, msg, strlen(msg));

    // zamykamy polaczenie
    SSL_shutdown(ssl);

    // czyscimy pamiec
    close(sd);
    SSL_free(ssl);
    SSL_CTX_free( ctx );
}
