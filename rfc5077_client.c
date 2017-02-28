/*
 * Created by ZhiHui Liu on 10/26/16.
 */

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>


typedef struct {
    char                    *ip;
    struct sockaddr_in      sin;
} host_t;


static int                  tries = 1;
static int                  enable_ticket = 0;
static int                  reuse_session = 0;
static char                 *sni = NULL;
static char                 *url = "/";
static char                 *ua = "User-Agent: Mozilla/5.0 (X11; Linux x86_64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.92 Safari/537.36";

static int                  reused = 0;
static time_t               total_ms = 0;


int main(int argc, char * const argv[])
{
    int                         fd, opt, tries;
    int                         port, i, j, k, host_n;
    int                         len, verbose;
    char                        *sni = NULL;
    char                        *ip;
    SSL_CTX                     *ctx;
    struct timeval              st, et;
    struct sockaddr_in          *sin;
    SSL                         *ssl;
    host_t                      *hosts = NULL;
    SSL_SESSION                 *session;
    char                        request[4096], id[512], *ptr;
    char                        response[4096], ticket[512];

    verbose = 0;
    tries = 5;
    port = 443;
    host_n = 0;

    while((opt = getopt(argc, argv, ":rtvs:p:u:n:h:")) != -1) {
        switch (opt) {
            case 's':
                sni = optarg;
                break;

            case 'p':
                port = atoi(optarg);
                if(port < 1 || port > 65531) {
                    exit(0);
                }

                break;
            case 'u':
                url = optarg;
                break;

            case 'n':
                tries = atoi(optarg);
                break;

            case 'r':
                reuse_session = 1;
                break;

            case 'v':
                verbose = 1;
                break;

            case 't':
                enable_ticket = 1;
                break;

            case 'h':
                hosts = malloc(8 * sizeof(host_t));
                if(hosts == NULL) {
                    return -1;
                }

                hosts[0].ip = strtok(optarg, " ");
                host_n = 1;

                for(i = 1; i < 8; ++i) {
                    hosts[i].ip = strtok(NULL, " ");
                    if(hosts[i].ip == NULL) {
                        break;
                    }

                    host_n += 1;
                }

                break;

            default:
                printf("Usage: ./ssl_session -s www.xxx.com -p [port] -n [tries] -h ip\n");
                printf("      -s      SNI name\n");
                printf("      -p      port\n");
                printf("      -n      try n times\n");
                printf("      -r      reuse session(both ticket and id)\n");
                printf("      -h      hosts\n");
                printf("      -t      enable ticket\n\n");

                return 0;
        }
    }

    if(hosts == NULL) {
        printf("host ip must be specified\n");
        return -1;
    }

    if(sni == NULL) {
        printf("sni must be specified\n");
        return -1;
    }

    for(i = 0; i < host_n; ++i) {
        ip = hosts[i].ip;
        sin = &hosts[i].sin;

        sin->sin_family = AF_INET;
        sin->sin_port = htons(port);
        sin->sin_addr.s_addr = inet_addr(ip);

        if(sin->sin_addr.s_addr == INADDR_NONE) {
            printf("invalid host");
            free(hosts);
            return -1;
        }
    }

    SSL_load_error_strings();
    SSL_library_init();
    OpenSSL_add_all_algorithms();

    ctx = SSL_CTX_new(TLSv1_2_client_method());
    // ctx = SSL_CTX_new(SSLv3_client_method());
    // ctx = SSL_CTX_new(SSLv23_client_method());

    if(ctx == NULL) {
        return -1;
    }

    if(enable_ticket) {
        printf("tls ticket is enabled\n");
    } else {
        SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);
    }

    if(reuse_session) {
        printf("tls session resumption is enabled\n");
        SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_AUTO_CLEAR);
    } else {
        printf("TLS session resumption is disabled\n");
        SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    }

    printf("\n tries |   ip address     |             chiper            | read  |  write |  time  | reused |"
                   "                                session id                              "
                   "|          session ticket name                         \n");


    ssl = SSL_new(ctx);
    if(enable_ticket == 0) {
        SSL_set_options(ssl, SSL_OP_NO_TICKET);
    }

    memset(request, 0, 4096);
    len = sprintf(request, "GET %s HTTP/1.0\r\nHost: %s\r\nUser-Agent: %s\r\n\r\n", url, sni, ua);


    for(i = 0; i < tries; ++i) {

        for(j = 0; j < host_n; ++j) {
            fd = socket(AF_INET, SOCK_STREAM, 0);
            if(fd == -1) {
                goto error;
            }

            gettimeofday(&st, NULL);

            if(connect(fd, (struct sockaddr *)&hosts[j].sin, sizeof(struct sockaddr_in)) != 0) {
                goto error;
            }

            SSL_set_fd(ssl, fd);
            SSL_connect(ssl);

            gettimeofday(&et, NULL);

            total_ms += (et.tv_sec - st.tv_sec) * 1000 + (et.tv_usec - st.tv_usec) / 1000;

            if(SSL_session_reused(ssl)) {
                reused += 1;
            }

            session = SSL_get0_session(ssl);
            if(session == NULL) {
                printf("no session\n");
            }

            /* io */
            if(SSL_write(ssl, request, len) != len) {
                goto error;
            }

            memset(response, 0, 4096);
            SSL_read(ssl, response, 4096);

            memset(id, 0, 512);

            ptr = id;
            for(k = 0; k < session->session_id_length; ++k) {
                sprintf(ptr, "%02X", session->session_id[k]);
                ptr += 2;
            }

            memset(ticket, 0, 512);
            ptr = ticket;
            for(k = 0; k < ((session->tlsext_ticklen) ? 24 : 0); ++k) {
                sprintf(ptr, "%02X", session->tlsext_tick[k]);
                ptr += 2;
            }

            printf(" % 4d  | %15s  |  %27s  | %5ld | %5ld  | % 4ldms |    %s   |    %s    | %s... \n",
                   i + 1,
                   hosts[j].ip,
                   session->cipher ? session->cipher->name : "NULL",
                   ssl->rbio->num_read,
                   ssl->wbio->num_write,
                   (et.tv_sec - st.tv_sec) * 1000 + (et.tv_usec - st.tv_usec) / 1000,
                   SSL_session_reused(ssl) ? "✔" : "✘",
                   (session->session_id_length == 0) ? "session_id : none" : id,
                   (session->tlsext_ticklen == 0) ? "ticket : none" : ticket);


            SSL_shutdown(ssl);
            close(fd);
        }

    }

error:
    printf("\n\navrg request time %ldms\n", total_ms / tries);
    printf("session reused %d times(total %d)\n", reused, tries);
    printf("time used %ldms for %d requests\n\n", total_ms, tries);

    SSL_CTX_free(ctx);
    return 0;
}

