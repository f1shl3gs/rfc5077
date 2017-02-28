/*
 * Created by ZhiHui Liu on 2/28/17.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/rand.h>


static char *crt = "/home/fishlegs/Workspaces/tengine/build/conf/ssl/lzh.crt";
static char *key = "/home/fishlegs/Workspaces/tengine/build/conf/ssl/lzh.key";
static char *response = "HTTP/1.1 200 OK\n"
        "Cache-Control: private, max-age=0\n"
        "Content-Length: 13\n"
        "Content-Type: text/plain\n\n"
        "hello world\n";

typedef struct {
    u_char                  name[16];
    u_char                  aes_key[16];
    u_char                  hmac_key[16];
} ssl_ticket_key_t;

static int a = 0;
static ssl_ticket_key_t     keys[3];


static int ssl_session_ticket_key_callbacke(SSL *ssl, unsigned char *name,
    unsigned char *iv, EVP_CIPHER_CTX *ectx, HMAC_CTX *hctx, int enc);


int main(int argc, const char *argv[])
{
    int                     s, fd, len, i;
    u_char                  buf[1024];
    struct sockaddr_in      sin;
    SSL_CTX                 *ctx;
    SSL                     *ssl;
    SSL_SESSION             *session;

    SSL_load_error_strings();
    SSL_library_init();
    ctx = SSL_CTX_new(TLSv1_2_server_method());
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_ALL | SSL_OP_NO_COMPRESSION);

    if(SSL_CTX_use_certificate_file(ctx, crt, SSL_FILETYPE_PEM) != 1) {
        return -1;
    }

    if(SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) != 1) {
        return -1;
    }

    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_SERVER);


    /* listen */
    sin.sin_family = AF_INET;
    sin.sin_port = htons(9000);
    sin.sin_addr.s_addr = inet_addr("127.0.0.1");

    s = socket(AF_INET, SOCK_STREAM, 0);
    if(s == -1) {
        return -1;
    }

    if(bind(s, (struct sockaddr *)&sin, sizeof(struct sockaddr_in)) != 0) {
        return -1;
    }

    if(listen(s, 128) != 0) {
        return -1;
    }

    RAND_pseudo_bytes(keys[0].name, 48);
    RAND_pseudo_bytes(keys[1].name, 48);
    RAND_pseudo_bytes(keys[2].name, 48);

    SSL_CTX_set_tlsext_ticket_key_cb(ctx, ssl_session_ticket_key_callbacke);

    /* server loop */
    for(i = 1; /* void */; ++i) {
        fd = accept(s, NULL, 0);
        if(fd == -1) {
            break;
        }

        ssl = SSL_new(ctx);
        SSL_set_mode(ssl, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_RELEASE_BUFFERS);
        SSL_set_accept_state(ssl);
        SSL_set_fd(ssl, fd);

        SSL_accept(ssl);

        session = SSL_get0_session(ssl);
        sprintf(buf, "/home/fishlegs/Workspaces/tengine/test/sessions/%d.txt", i);
        FILE            *fp;

        fp = fopen(buf, "w");
        SSL_SESSION_print_fp(fp, session);
        fclose(fp);

        SSL_read(ssl, buf, 1024);

        SSL_write(ssl, response, strlen(response));

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(fd);

        if(i % 5 == 0) {
            memcpy(keys[2].name, keys[1].name, 48);
            memcpy(keys[1].name, keys[0].name, 48);
            RAND_pseudo_bytes(keys[0].name, 48);

            printf("update tickets\n");
        }
    }

    close(s);
    SSL_CTX_free(ctx);

    return 0;
}


static int ssl_session_ticket_key_callbacke(SSL *ssl, unsigned char *name,
    unsigned char *iv, EVP_CIPHER_CTX *ectx, HMAC_CTX *hctx, int enc)
{
    int                 i;

    if(enc == 1) {
        /* encrypt session ticket */

        RAND_pseudo_bytes(iv, 16);
        EVP_EncryptInit_ex(ectx, EVP_aes_128_cbc(), NULL, keys[0].aes_key, iv);
        HMAC_Init_ex(hctx, keys[0].hmac_key, 16, EVP_sha256(), NULL);

        memcpy(name, keys[0].name, 16);

        return 0;
    } else {
        for(i = 0; i < 3; ++i) {
            if(memcmp(name, keys[i].name, 16) == 0) {
                goto found;
            }
        }

        return 0;

    found:
        HMAC_Init_ex(hctx, keys[i].hmac_key, 16, EVP_sha256(), NULL);
        EVP_DecryptInit_ex(ectx, EVP_aes_128_cbc(), NULL, keys[i].aes_key, iv);

        if(i != 0) {
            printf("renew a ticket\n");
        }

        return (i == 0) ? 1 : 2;
    }
}
