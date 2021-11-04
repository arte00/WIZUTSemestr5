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
#define CERTF "servercert.pem"
#define KEYF "serverkey.pem"
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
    int err, port;
    int listen_sd;
    int sd;
    struct sockaddr_in sa_serv;
    struct sockaddr_in sa_cli;
    size_t client_len;
    SSL_CTX* ctx;
    SSL *ssl;
    X509 *client_cert;
    char *str;
    char buf[4096];
    const SSL_METHOD *meth;

    if (argc != 2) {
       fprintf(stderr,"usage: server port\n");
       exit(1);
    }

    if ((port = atoi(argv[1])) == 0)
    {
       perror("Bledny numer portu");
       exit(1);
    }

    // Inicjowanie open ssl
    SSLeay_add_ssl_algorithms();
    meth = SSLv23_server_method();
    SSL_load_error_strings();

    // tu tworzymy obiekt SSL_CTX
    ctx = SSL_CTX_new (meth);

    // Sprawdzenie poprawnosci
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
    // nie powiedzie to polaczenie jest przerywane)
    // SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verify_callback);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);

    // ustawienie maxymalnej hierarchi do 4 poziomow
    SSL_CTX_set_verify_depth(ctx, 4);

    // przygotowanie tcp
    listen_sd = socket( AF_INET, SOCK_STREAM, 0);
    CHK_ERR(listen_sd, "socket");

    memset( &sa_serv, '\0', sizeof(sa_serv));
    sa_serv.sin_family = AF_INET;
    sa_serv.sin_addr.s_addr = htonl(INADDR_ANY);

    // port serwera
    sa_serv.sin_port = htons(port);

    err = bind (listen_sd, (struct sockaddr*) &sa_serv, sizeof(sa_serv));
    CHK_ERR(err, "bind");

    err = listen (listen_sd, 5);
    CHK_ERR( err, "listen");

    client_len = sizeof( sa_cli);
    sd = accept (listen_sd, (struct sockaddr*)&sa_cli, &client_len);
    CHK_ERR( sd, "accept");
    close( listen_sd );

    printf("Polaczenie z %lx, port %x\n", sa_cli.sin_addr.s_addr, sa_cli.sin_port);

    // utworzenie obiektu ssl
    ssl= SSL_new(ctx);
    CHK_NULL(ssl);

    // dowiazanie do struktury ssl instniejacego deskryptora tcp
    SSL_set_fd(ssl, sd);

    err = SSL_accept(ssl);
    CHK_SSL(err);

    printf("polaczenie SSL uzywa %s\n", SSL_get_cipher(ssl));

    // pobranie certyfikatu klienta
    client_cert = SSL_get_peer_certificate(ssl);
    if(client_cert != NULL)
    {
        printf("Certyfikat klienta:\n");
        str = X509_NAME_oneline (X509_get_subject_name (client_cert), 0, 0);
        CHK_NULL(str);
        printf( "\n temat: %s\n", str);
        free (str);

        str = X509_NAME_oneline( X509_get_issuer_name(client_cert), 0, 0);
        printf("Wydany przez: %s\n", str);
        CHK_NULL(str);
        free(str);
        X509_free (client_cert);
    }
    else
    {
        printf("Klient nie posiada certyfikatu.\n");
    }

    // Wymiana danych
    err = SSL_read( ssl, buf, sizeof(buf) -1 );

    // sprawdzamy poprawnosc
    CHK_SSL(err);
    buf[err]='\0';
    printf( "Otrzymano %d znakow: '%s'\n", err, buf);

    // zamykamy polaczenie
    close(sd);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
}
