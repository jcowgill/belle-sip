/*
	belle-sip - SIP (RFC3261) library.
    Copyright (C) 2013  Belledonne Communications SARL

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "belle_sip_internal.h"
#include "stream_channel.h"

/* Uncomment to get very verbose mbedtls logs*/
//#define MBEDTLS_DEBUG_LEVEL 2
#include <mbedtls/ssl.h>
#include <mbedtls/error.h>
#include <mbedtls/pem.h>
#include <mbedtls/base64.h>
#include <mbedtls/x509.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/sha1.h>
#include <mbedtls/sha256.h>
#include <mbedtls/sha512.h>
#include <mbedtls/net.h>
#include <mbedtls/debug.h>

struct belle_sip_certificates_chain {
	belle_sip_object_t objet;
	mbedtls_x509_crt cert;
};

struct belle_sip_signing_key {
	belle_sip_object_t objet;
	mbedtls_pk_context key;
};


/**
 * Retrieve key or certificate in a string(PEM format)
 */
char *belle_sip_certificates_chain_get_pem(belle_sip_certificates_chain_t *cert) {
	char *pem_certificate = NULL;
	size_t olen=0;
	if (cert == NULL) return NULL;

	pem_certificate = (char*)belle_sip_malloc(4096);
	mbedtls_pem_write_buffer("-----BEGIN CERTIFICATE-----\n", "-----END CERTIFICATE-----\n", cert->cert.raw.p, cert->cert.raw.len, (unsigned char*)pem_certificate, 4096, &olen );
	return pem_certificate;
}

char *belle_sip_signing_key_get_pem(belle_sip_signing_key_t *key) {
	char *pem_key;
	if (key == NULL) return NULL;
	pem_key = (char *)belle_sip_malloc(4096);
	mbedtls_pk_write_key_pem( &(key->key), (unsigned char *)pem_key, 4096);
	return pem_key;
}

/*************tls********/
// SSL verification callback prototype
// der - raw certificate data, in DER format
// length - length of certificate DER data
// depth - position of certificate in cert chain, ending at 0 = root or top
// flags - verification state for CURRENT certificate only
typedef int (*verify_cb_error_cb_t)(unsigned char *der, int length, int depth, uint32_t *flags);
static verify_cb_error_cb_t tls_verify_cb_error_cb = NULL;

static int tls_process_data(belle_sip_channel_t *obj,unsigned int revents);

struct belle_sip_tls_channel{
	belle_sip_stream_channel_t base;
	mbedtls_ssl_context sslctx;
	mbedtls_ssl_config sslconf;
	mbedtls_x509_crt root_ca;
	struct sockaddr_storage ss;
	socklen_t socklen;
	int socket_connected;
	char *cur_debug_msg;
	belle_sip_certificates_chain_t* client_cert_chain;
	belle_sip_signing_key_t* client_cert_key;
	belle_tls_verify_policy_t *verify_ctx;
	int http_proxy_connected;
	belle_sip_resolver_context_t *http_proxy_resolver_ctx;
};

static void tls_channel_close(belle_sip_tls_channel_t *obj){
	belle_sip_socket_t sock = belle_sip_source_get_socket((belle_sip_source_t*)obj);
	if (sock!=-1 && belle_sip_channel_get_state((belle_sip_channel_t*)obj)!=BELLE_SIP_CHANNEL_ERROR)
		mbedtls_ssl_close_notify(&obj->sslctx);
	stream_channel_close((belle_sip_stream_channel_t*)obj);
	mbedtls_ssl_session_reset(&obj->sslctx);
	obj->socket_connected=0;
}

static void tls_channel_uninit(belle_sip_tls_channel_t *obj){
	belle_sip_socket_t sock = belle_sip_source_get_socket((belle_sip_source_t*)obj);
	if (sock!=(belle_sip_socket_t)-1)
		tls_channel_close(obj);
	mbedtls_ssl_free(&obj->sslctx);
	mbedtls_ssl_config_free(&obj->sslconf);
	mbedtls_x509_crt_free(&obj->root_ca);
	if (obj->cur_debug_msg)
		belle_sip_free(obj->cur_debug_msg);
	belle_sip_object_unref(obj->verify_ctx);
	if (obj->client_cert_chain) belle_sip_object_unref(obj->client_cert_chain);
	if (obj->client_cert_key) belle_sip_object_unref(obj->client_cert_key);
	if (obj->http_proxy_resolver_ctx) belle_sip_object_unref(obj->http_proxy_resolver_ctx);
}

static int tls_channel_send(belle_sip_channel_t *obj, const void *buf, size_t buflen){
	belle_sip_tls_channel_t* channel = (belle_sip_tls_channel_t*)obj;
	int err = mbedtls_ssl_write(&channel->sslctx,buf,buflen);
	if (err<0){
		char tmp[256]={0};
		if (err==MBEDTLS_ERR_SSL_WANT_WRITE) return -BELLESIP_EWOULDBLOCK;
		mbedtls_strerror(err,tmp,sizeof(tmp));
		belle_sip_error("Channel [%p]: ssl_write() error [%i]: %s",obj,err,tmp);
	}
	return err;
}

static int tls_channel_recv(belle_sip_channel_t *obj, void *buf, size_t buflen){
	belle_sip_tls_channel_t* channel = (belle_sip_tls_channel_t*)obj;
	int err = mbedtls_ssl_read(&channel->sslctx,buf,buflen);
	if (err==MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) return 0;
	if (err<0){
		char tmp[256]={0};
		if (err==MBEDTLS_ERR_SSL_WANT_READ) return -BELLESIP_EWOULDBLOCK;
		mbedtls_strerror(err,tmp,sizeof(tmp));
		belle_sip_error("Channel [%p]: ssl_read() error [%i]: %s",obj, err, tmp);
	}
	return err;
}

static int tls_channel_connect_to(belle_sip_channel_t *obj, const struct addrinfo *ai){
	int err;
	err= stream_channel_connect((belle_sip_stream_channel_t*)obj,ai);
	if (err==0){
		belle_sip_source_set_notify((belle_sip_source_t *)obj, (belle_sip_source_func_t)tls_process_data);
		return 0;
	}
	return -1;
}

static void http_proxy_res_done(void *data, const char *name, struct addrinfo *ai_list){
	belle_sip_tls_channel_t *obj=(belle_sip_tls_channel_t*)data;
	if (obj->http_proxy_resolver_ctx){
		belle_sip_object_unref(obj->http_proxy_resolver_ctx);
		obj->http_proxy_resolver_ctx=NULL;
	}
	if (ai_list){
		tls_channel_connect_to((belle_sip_channel_t *)obj,ai_list);
		belle_sip_freeaddrinfo(ai_list);
	}else{
		belle_sip_error("%s: DNS resolution failed for %s", __FUNCTION__, name);
		channel_set_state((belle_sip_channel_t*)obj,BELLE_SIP_CHANNEL_ERROR);
	}
}

static int tls_channel_connect(belle_sip_channel_t *obj, const struct addrinfo *ai){
	belle_sip_tls_channel_t *channel=(belle_sip_tls_channel_t*)obj;
	if (obj->stack->http_proxy_host) {
		belle_sip_message("Resolving http proxy addr [%s] for channel [%p]",obj->stack->http_proxy_host,obj);
		/*assume ai family is the same*/
		channel->http_proxy_resolver_ctx = belle_sip_stack_resolve_a(obj->stack, obj->stack->http_proxy_host, obj->stack->http_proxy_port, obj->ai_family, http_proxy_res_done, obj);
		if (channel->http_proxy_resolver_ctx) belle_sip_object_ref(channel->http_proxy_resolver_ctx);
		return 0;
	} else {
		return tls_channel_connect_to(obj, ai);
	}
}

BELLE_SIP_DECLARE_CUSTOM_VPTR_BEGIN(belle_sip_tls_channel_t,belle_sip_stream_channel_t)
BELLE_SIP_DECLARE_CUSTOM_VPTR_END

BELLE_SIP_DECLARE_NO_IMPLEMENTED_INTERFACES(belle_sip_tls_channel_t);

BELLE_SIP_INSTANCIATE_CUSTOM_VPTR_BEGIN(belle_sip_tls_channel_t)
	{
		{
			{
				BELLE_SIP_VPTR_INIT(belle_sip_tls_channel_t,belle_sip_stream_channel_t,FALSE),
				(belle_sip_object_destroy_t)tls_channel_uninit,
				NULL,
				NULL
			},
			"TLS",
			1, /*is_reliable*/
			tls_channel_connect,
			tls_channel_send,
			tls_channel_recv,
			(void (*)(belle_sip_channel_t*))tls_channel_close
		}
	}
BELLE_SIP_INSTANCIATE_CUSTOM_VPTR_END

static int tls_channel_handshake(belle_sip_tls_channel_t *channel) {
	int ret;
	while( channel->sslctx.state != MBEDTLS_SSL_HANDSHAKE_OVER ) {
		if ((ret = mbedtls_ssl_handshake_step( &channel->sslctx ))) {
			break;
		}
		if (channel->sslctx.state == MBEDTLS_SSL_CLIENT_CERTIFICATE && channel->sslctx.client_auth >0) {
			BELLE_SIP_INVOKE_LISTENERS_ARG1_ARG2(	channel->base.base.listeners
					,belle_sip_channel_listener_t
					,on_auth_requested
					,&channel->base.base
					,NULL/*not set yet*/);

			if (channel->client_cert_chain && channel->client_cert_key) {
				int err;
				char tmp[512]={0};
				mbedtls_x509_crt_info(tmp,sizeof(tmp)-1,"",&channel->client_cert_chain->cert);
				belle_sip_message("Channel [%p]  found client  certificate:\n%s",channel,tmp);
                                /* allows public keys other than RSA */
				if ((err = mbedtls_ssl_set_hs_own_cert(&channel->sslctx, &channel->client_cert_chain->cert,
								&channel->client_cert_key->key))) {
					mbedtls_strerror(err,tmp,sizeof(tmp)-1);
					belle_sip_error("Channel [%p] cannot ssl_set_own_cert [%s]",channel,tmp);
				}
			}
		}

	}
	return ret;
}

static int tls_process_handshake(belle_sip_channel_t *obj){
	belle_sip_tls_channel_t* channel=(belle_sip_tls_channel_t*)obj;
	int err=tls_channel_handshake(channel);
	if (err==0){
		belle_sip_message("Channel [%p]: SSL handshake finished.",obj);
		belle_sip_source_set_timeout((belle_sip_source_t*)obj,-1);
		belle_sip_channel_set_ready(obj,(struct sockaddr*)&channel->ss,channel->socklen);
	}else if (err==MBEDTLS_ERR_SSL_WANT_READ || err==MBEDTLS_ERR_SSL_WANT_WRITE){
		belle_sip_message("Channel [%p]: SSL handshake in progress...",obj);
	}else{
		char tmp[128];
		mbedtls_strerror(err,tmp,sizeof(tmp));
		belle_sip_error("Channel [%p]: SSL handshake failed : %s",obj,tmp);
		return -1;
	}
	return 0;
}

static int tls_process_http_connect(belle_sip_tls_channel_t *obj) {
	char* request;
	belle_sip_channel_t *channel = (belle_sip_channel_t *)obj;
	int err;
	char ip[64];
	int port;
	belle_sip_addrinfo_to_ip(channel->current_peer,ip,sizeof(ip),&port);
	
	request = belle_sip_strdup_printf("CONNECT %s:%i HTTP/1.1\r\nProxy-Connection: keep-alive\r\nConnection: keep-alive\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\n"
									  ,ip
									  ,port
									  ,ip);
	
	if (channel->stack->http_proxy_username && channel->stack->http_proxy_passwd) {
		char *username_passwd = belle_sip_strdup_printf("%s:%s",channel->stack->http_proxy_username,channel->stack->http_proxy_passwd);
		size_t username_passwd_length = strlen(username_passwd);
		unsigned char *encoded_username_paswd = belle_sip_malloc(2*username_passwd_length);
		size_t encoded_username_paswd_length;

		mbedtls_base64_encode(encoded_username_paswd, username_passwd_length * 2, &encoded_username_paswd_length,
			(const unsigned char *) username_passwd, username_passwd_length);

		request = belle_sip_strcat_printf(request, "Proxy-Authorization: Basic %s\r\n",encoded_username_paswd);
		belle_sip_free(username_passwd);
		belle_sip_free(encoded_username_paswd);
	}
	
	request = belle_sip_strcat_printf(request,"\r\n");
	err = send(belle_sip_source_get_socket((belle_sip_source_t*)obj),request,strlen(request),0);
	belle_sip_free(request);
	if (err <= 0) {
		belle_sip_error("tls_process_http_connect: fail to send connect request to http proxy [%s:%i] status [%s]"
						,channel->stack->http_proxy_host
						,channel->stack->http_proxy_port
						,strerror(errno));
		return -1;
	}
	return 0;
}
static int tls_process_data(belle_sip_channel_t *obj,unsigned int revents){
	belle_sip_tls_channel_t* channel=(belle_sip_tls_channel_t*)obj;
	int err;
	
	if (obj->state == BELLE_SIP_CHANNEL_CONNECTING ) {
		if (!channel->socket_connected) {
			channel->socklen=sizeof(channel->ss);
			if (finalize_stream_connection((belle_sip_stream_channel_t*)obj,revents,(struct sockaddr*)&channel->ss,&channel->socklen)) {
				goto process_error;
			}
			
			channel->socket_connected=1;
			belle_sip_source_set_events((belle_sip_source_t*)channel,BELLE_SIP_EVENT_READ|BELLE_SIP_EVENT_ERROR);
			belle_sip_source_set_timeout((belle_sip_source_t*)obj,belle_sip_stack_get_transport_timeout(obj->stack));
			if (obj->stack->http_proxy_host) {
				belle_sip_message("Channel [%p]: Connected at TCP level, now doing http proxy connect",obj);
				if (tls_process_http_connect(channel)) goto process_error;
			} else {
				belle_sip_message("Channel [%p]: Connected at TCP level, now doing TLS handshake",obj);
				if (tls_process_handshake(obj)==-1) goto process_error;
			}
		} else if (obj->stack->http_proxy_host && !channel->http_proxy_connected) {
			char response[256];
			err = stream_channel_recv((belle_sip_stream_channel_t*)obj,response,sizeof(response));
			if (err<0 ){
				belle_sip_error("Channel [%p]: connection refused by http proxy [%s:%i] status [%s]"
								,channel
								,obj->stack->http_proxy_host
								,obj->stack->http_proxy_port
								,strerror(errno));
				goto process_error;
			} else if (strstr(response,"407")) {
				belle_sip_error("Channel [%p]: auth requested, provide user/passwd by http proxy [%s:%i]"
								,channel
								,obj->stack->http_proxy_host
								,obj->stack->http_proxy_port);
				goto process_error;
			} else if (strstr(response,"200")) {
				belle_sip_message("Channel [%p]: connected to http proxy, doing TLS handshake [%s:%i] "
								  ,channel
								  ,obj->stack->http_proxy_host
								  ,obj->stack->http_proxy_port);
				channel->http_proxy_connected = 1;
				if (tls_process_handshake(obj)==-1) goto process_error;
			} else {
				belle_sip_error("Channel [%p]: connection refused by http proxy [%s:%i]"
								,channel
								,obj->stack->http_proxy_host
								,obj->stack->http_proxy_port);
				goto process_error;
			}
			
		} else {
			if (revents & BELLE_SIP_EVENT_READ){
				if (tls_process_handshake(obj)==-1) goto process_error;
			}else if (revents==BELLE_SIP_EVENT_TIMEOUT){
				belle_sip_error("channel [%p]: SSL handshake took too much time.",obj);
				goto process_error;
			}else{
				belle_sip_warning("channel [%p]: unexpected event [%i] during TLS handshake.",obj,revents);
			}
		}
	} else if ( obj->state == BELLE_SIP_CHANNEL_READY) {
		return belle_sip_channel_process_data(obj,revents);
	} else {
		belle_sip_warning("Unexpected event [%i], for channel [%p]",revents,channel);
		return BELLE_SIP_STOP;
	}
	return BELLE_SIP_CONTINUE;
	
process_error:
	belle_sip_error("Cannot connect to [%s://%s:%i]",belle_sip_channel_get_transport_name(obj),obj->peer_name,obj->peer_port);
	channel_set_state(obj,BELLE_SIP_CHANNEL_ERROR);
	return BELLE_SIP_STOP;
}

static int mbedtls_read(void * ctx, unsigned char *buf, size_t len ){
	belle_sip_stream_channel_t *super=(belle_sip_stream_channel_t *)ctx;
	
	int ret = stream_channel_recv(super,buf,len);

	if (ret<0){
		ret=-ret;
		if (ret==BELLESIP_EWOULDBLOCK || ret==BELLESIP_EINPROGRESS || ret == EINTR )
			return MBEDTLS_ERR_SSL_WANT_READ;
		return MBEDTLS_ERR_NET_CONN_RESET;
	}
	return ret;
}

static int mbedtls_write(void * ctx, const unsigned char *buf, size_t len ){
	belle_sip_stream_channel_t *super=(belle_sip_stream_channel_t *)ctx;
	
	int ret = stream_channel_send(super, buf, len);

	if (ret<0){
		ret=-ret;
		if (ret==BELLESIP_EWOULDBLOCK || ret==BELLESIP_EINPROGRESS || ret == EINTR )
			return MBEDTLS_ERR_SSL_WANT_WRITE;
		return MBEDTLS_ERR_NET_CONN_RESET;
	}
	return ret;
}

static int random_generator(void *ctx, unsigned char *ptr, size_t size){
	belle_sip_random_bytes(ptr, size);
	return 0;
}

static const char *mbedtls_certflags_to_string(char *buf, size_t size, int flags){
	size_t i=0;
	
	memset(buf,0,size);
	size--;
	
	if (i<size && (flags & MBEDTLS_X509_BADCERT_EXPIRED))
		i+=snprintf(buf+i,size-i,"expired ");
	if (i<size && (flags & MBEDTLS_X509_BADCERT_REVOKED))
		i+=snprintf(buf+i,size-i,"revoked ");
	if (i<size && (flags & MBEDTLS_X509_BADCERT_CN_MISMATCH))
		i+=snprintf(buf+i,size-i,"CN-mismatch ");
	if (i<size && (flags & MBEDTLS_X509_BADCERT_NOT_TRUSTED))
		i+=snprintf(buf+i,size-i,"not-trusted ");
	if (i<size && (flags & MBEDTLS_X509_BADCERT_MISSING))
		i+=snprintf(buf+i,size-i,"missing ");
	if (i<size && (flags & MBEDTLS_X509_BADCRL_NOT_TRUSTED))
		i+=snprintf(buf+i,size-i,"crl-not-trusted ");
	if (i<size && (flags & MBEDTLS_X509_BADCRL_EXPIRED))
		i+=snprintf(buf+i,size-i,"crl-expired ");
	return buf;
}

// shim the default mbedTLS certificate handling by adding an external callback
// see "verify_cb_error_cb_t" for the function signature
int belle_sip_tls_set_verify_error_cb(void * callback)
{
	if (callback) {
        tls_verify_cb_error_cb = (verify_cb_error_cb_t)callback;
		belle_sip_message("belle_sip_tls_set_verify_error_cb: callback set");
	} else {
        tls_verify_cb_error_cb = NULL;
		belle_sip_message("belle_sip_tls_set_verify_error_cb: callback cleared");
	}
	return 0;
}

//
// Augment certificate verification with certificates stored outside rootca.pem
// mbedTLS calls the verify_cb with each cert in the chain; flags apply to the
// current certificate until depth is 0;
//
// NOTES:
// 1) rootca.pem *must* have at least one valid certificate, or mbedTLS
// does not attempt to verify any certificates
// 2) callback must return 0; non-zero indicates that the verification process failed
// 3) flags should be saved off and cleared for each certificate where depth>0
// 4) return final verification result in *flags when depth == 0
// 5) callback must disable calls to linphone_core_iterate while running
//

int belle_sip_verify_cb_error_wrapper(mbedtls_x509_crt *cert, int depth, uint32_t *flags){
	int rc = 0;
	unsigned char *der = NULL;

	// do nothing if the callback is not set
	if (!tls_verify_cb_error_cb) {
		return 0;
	}

	belle_sip_message("belle_sip_verify_cb_error_wrapper: depth=[%d], flags=[%u]:\n", depth, (unsigned)*flags);

	der = belle_sip_malloc(cert->raw.len + 1);
	if (der == NULL) {
		// leave the flags alone and just return to the library
		belle_sip_error("belle_sip_verify_cb_error_wrapper: memory error\n");
		return 0;
	}

	// copy in and NULL terminate again for safety
	memcpy(der, cert->raw.p, cert->raw.len);
	der[cert->raw.len] = '\0';

	rc = tls_verify_cb_error_cb(der, cert->raw.len, depth, flags);

	belle_sip_message("belle_sip_verify_cb_error_wrapper: callback return rc: %d, flags: %u", rc, (unsigned)*flags);
	belle_sip_free(der);
	return rc;
}


static int belle_sip_ssl_verify(void *data, mbedtls_x509_crt *cert, int depth, uint32_t *flags){
	belle_tls_verify_policy_t *verify_ctx=(belle_tls_verify_policy_t*)data;
	const int tmp_size = 2048, flags_str_size = 256;
	char *tmp = belle_sip_malloc0(tmp_size);
	char *flags_str = belle_sip_malloc0(flags_str_size);
	int ret;
	
	mbedtls_x509_crt_info(tmp,tmp_size-1,"",cert);
	belle_sip_message("Found certificate depth=[%i], flags=[%s]:\n%s",
		depth,mbedtls_certflags_to_string(flags_str,flags_str_size-1,*flags),tmp);
	if (verify_ctx->exception_flags==BELLE_TLS_VERIFY_ANY_REASON){
		*flags=0;
	}else if (verify_ctx->exception_flags & BELLE_TLS_VERIFY_CN_MISMATCH){
		*flags&=~MBEDTLS_X509_BADCERT_CN_MISMATCH;
	}

	ret = belle_sip_verify_cb_error_wrapper(cert, depth, flags);

	belle_sip_free(flags_str);
	belle_sip_free(tmp);

	return ret;
}

static int belle_sip_tls_channel_load_root_ca(belle_sip_tls_channel_t *obj, const char *path){
	struct stat statbuf; 
	if (stat(path,&statbuf)==0){
		if (statbuf.st_mode & S_IFDIR){
			if (mbedtls_x509_crt_parse_path(&obj->root_ca,path)<0){
				belle_sip_error("Failed to load root ca from directory %s",path);
				return -1;
			}
		}else{
			if (mbedtls_x509_crt_parse_file(&obj->root_ca,path)<0){
				belle_sip_error("Failed to load root ca from file %s",path);
				return -1;
			}
		}
		return 0;
	}
	belle_sip_error("Could not load root ca from %s: %s",path,strerror(errno));
	return -1;
}

#ifdef MBEDTLS_DEBUG_LEVEL
/*
 * mbedtls does a lot of logs, some with newline, some without.
 * We need to concatenate logs without new line until a new line is found.
 */
static void ssl_debug_to_belle_sip(void *context, int level, const char* file, int line, const char *str){
	belle_sip_tls_channel_t *chan=(belle_sip_tls_channel_t*)context;
	int len=strlen(str);
	
	if (len>0 && (str[len-1]=='\n' || str[len-1]=='\r')){
		/*eliminate the newline*/
		char *tmp=belle_sip_strdup(str);
		tmp[len-1]=0;
		if (chan->cur_debug_msg){
			belle_sip_message("ssl: %s%s",chan->cur_debug_msg,tmp);
			belle_sip_free(chan->cur_debug_msg);
			chan->cur_debug_msg=NULL;
		}else belle_sip_message("ssl: %s",tmp);
		belle_sip_free(tmp);
	}else{
		if (chan->cur_debug_msg){
			char *tmp=belle_sip_strdup_printf("%s%s",chan->cur_debug_msg,str);
			belle_sip_free(chan->cur_debug_msg);
			chan->cur_debug_msg=tmp;
		}else chan->cur_debug_msg=belle_sip_strdup(str);
	}
}

#endif

belle_sip_channel_t * belle_sip_channel_new_tls(belle_sip_stack_t *stack, belle_tls_verify_policy_t *verify_ctx,const char *bindip, int localport, const char *peer_cname, const char *dest, int port){
	belle_sip_tls_channel_t *obj=belle_sip_object_new(belle_sip_tls_channel_t);
	belle_sip_stream_channel_t* super=(belle_sip_stream_channel_t*)obj;

	belle_sip_stream_channel_init_client(super
					,stack
					,bindip,localport,peer_cname,dest,port);

	mbedtls_ssl_config_init(&obj->sslconf);
	mbedtls_ssl_config_defaults(&obj->sslconf, MBEDTLS_SSL_IS_CLIENT,
			MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
#ifdef MBEDTLS_DEBUG_LEVEL
	mbedtls_ssl_conf_dbg(&obj->sslconf, ssl_debug_to_belle_sip, obj);
	mbedtls_debug_set_threshold(MBEDTLS_DEBUG_LEVEL);
#endif
	mbedtls_ssl_conf_authmode(&obj->sslconf, MBEDTLS_SSL_VERIFY_REQUIRED);
	if (verify_ctx->root_ca && belle_sip_tls_channel_load_root_ca(obj, verify_ctx->root_ca) == 0) {
		mbedtls_ssl_conf_ca_chain(&obj->sslconf, &obj->root_ca, NULL);
	}
	mbedtls_ssl_conf_rng(&obj->sslconf, random_generator, NULL);
	mbedtls_ssl_conf_verify(&obj->sslconf, belle_sip_ssl_verify, verify_ctx);

	mbedtls_ssl_init(&obj->sslctx);
	mbedtls_ssl_setup(&obj->sslctx, &obj->sslconf);
	mbedtls_ssl_set_bio(&obj->sslctx, obj, mbedtls_write, mbedtls_read, NULL);
	mbedtls_ssl_set_hostname(&obj->sslctx, super->base.peer_cname ? super->base.peer_cname : super->base.peer_name);

	obj->verify_ctx = (belle_tls_verify_policy_t *)belle_sip_object_ref(verify_ctx);
	return (belle_sip_channel_t *)obj;
}

void belle_sip_tls_channel_set_client_certificates_chain(belle_sip_tls_channel_t *channel, belle_sip_certificates_chain_t* cert_chain) {
	SET_OBJECT_PROPERTY(channel,client_cert_chain,cert_chain);

}
void belle_sip_tls_channel_set_client_certificate_key(belle_sip_tls_channel_t *channel, belle_sip_signing_key_t* key){
	SET_OBJECT_PROPERTY(channel,client_cert_key,key);
}



/**************************** belle_sip_certificates_chain_t **/


// Duplicates the given buffer with one extra null character
//  This ensures the returned buffer is always null terminated
//  This is nessesary for some mbedtls functions which now require a null
//  terminated buffer to be provided.
static char *extend_buffer(const char *buff, size_t size) {
	char *result = belle_sip_malloc(size + 1);
	memcpy(result, buff, size);
	result[size] = '\0';
	return result;
}

static int belle_sip_certificate_fill(belle_sip_certificates_chain_t* certificate,const char* buff, size_t size,belle_sip_certificate_raw_format_t format) {
	int err;
	unsigned char *extended_buff = (unsigned char *)extend_buffer(buff, size);

	err = mbedtls_x509_crt_parse(&certificate->cert, extended_buff, size + 1);
	belle_sip_free(extended_buff);

	if (err < 0) {
		char tmp[128];
		mbedtls_strerror(err,tmp,sizeof(tmp));
		belle_sip_error("cannot parse x509 cert because [%s]",tmp);
		return -1;
	}
	return 0;
}

static int belle_sip_certificate_fill_from_file(belle_sip_certificates_chain_t* certificate,const char* path,belle_sip_certificate_raw_format_t format) {
	int err;
	if ((err=mbedtls_x509_crt_parse_file(&certificate->cert, path)) <0) {
		char tmp[128];
		mbedtls_strerror(err,tmp,sizeof(tmp));
		belle_sip_error("cannot parse x509 cert because [%s]",tmp);
		return -1;
	}
	return 0;
}

/*belle_sip_certificate */
belle_sip_certificates_chain_t* belle_sip_certificates_chain_parse(const char* buff, size_t size,belle_sip_certificate_raw_format_t format) {
	belle_sip_certificates_chain_t* certificate = belle_sip_object_new(belle_sip_certificates_chain_t);

	if (belle_sip_certificate_fill(certificate,buff, size,format)) {
		belle_sip_object_unref(certificate);
		certificate=NULL;
	}

	return certificate;
}

belle_sip_certificates_chain_t* belle_sip_certificates_chain_parse_file(const char* path, belle_sip_certificate_raw_format_t format) {
	belle_sip_certificates_chain_t* certificate = belle_sip_object_new(belle_sip_certificates_chain_t);

	if (belle_sip_certificate_fill_from_file(certificate, path, format)) {
		belle_sip_object_unref(certificate);
		certificate=NULL;
	}

	return certificate;
}


/*
 * Parse all *.pem files in a given dir(non recursively) and return the one matching the given subject
 */
int belle_sip_get_certificate_and_pkey_in_dir(const char *path, const char *subject, belle_sip_certificates_chain_t **certificate, belle_sip_signing_key_t **pkey, belle_sip_certificate_raw_format_t format) {
	/* get all *.pem file from given path */
	belle_sip_list_t *file_list = belle_sip_parse_directory(path, ".pem");
	char *filename = NULL;

	file_list = belle_sip_list_pop_front(file_list, (void **)&filename);
	while (filename != NULL) {
		belle_sip_certificates_chain_t *found_certificate = belle_sip_certificates_chain_parse_file(filename, format);
		if (found_certificate != NULL) { /* there is a certificate in this file */
			char *subject_CNAME_begin, *subject_CNAME_end;
			belle_sip_signing_key_t *found_key;
			char name[500];
			memset( name, 0, sizeof(name) );
			mbedtls_x509_dn_gets( name, sizeof(name), &(found_certificate->cert.subject));
			/* parse subject to find the CN=xxx, field. There may be no , at the and but a \0 */
			subject_CNAME_begin = strstr(name, "CN=");
			if (subject_CNAME_begin!=NULL) {
				subject_CNAME_begin+=3;
				subject_CNAME_end = strstr(subject_CNAME_begin, ",");
				if (subject_CNAME_end != NULL) {
					*subject_CNAME_end = '\0';
				}
				if (strcmp(subject_CNAME_begin, subject)==0) { /* subject CNAME match the one we are looking for*/
					/* do we have a key too ? */
					found_key = belle_sip_signing_key_parse_file(filename, NULL);
					if (found_key!=NULL) {
						*certificate = found_certificate;
						*pkey = found_key;
						belle_sip_free(filename);
						belle_sip_list_free_with_data(file_list, belle_sip_free); /* free possible rest of list */
						return 0;
					}
				}
			}
		}
		belle_sip_free(filename);
		file_list = belle_sip_list_pop_front(file_list, (void **)&filename);
	}
	return -1;
}

int belle_sip_generate_self_signed_certificate(const char* path, const char *subject, belle_sip_certificates_chain_t **certificate, belle_sip_signing_key_t **pkey) {
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	int ret;
	mbedtls_mpi serial;
	mbedtls_x509write_cert crt;
	FILE *fd;
	char file_buffer[8192];
	size_t file_buffer_len = 0;
	char *name_with_path;
	int path_length;
	char formatted_subject[512];

	/* subject may be a sip URL or linphone-dtls-default-identity, add CN= before it to make a valid name */
	memcpy(formatted_subject, "CN=", 3);
	memcpy(formatted_subject+3, subject, strlen(subject)+1); /* +1 to get the \0 termination */

	/* allocate certificate and key */
	*pkey = belle_sip_object_new(belle_sip_signing_key_t);
	*certificate = belle_sip_object_new(belle_sip_certificates_chain_t);

	mbedtls_entropy_init( &entropy );
	mbedtls_ctr_drbg_init(&ctr_drbg);
	if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0)) != 0) {
		belle_sip_error("Certificate generation can't init ctr_drbg: -%x", -ret);
		return -1;
	}

	/* generate 3072 bits RSA public/private key */
	mbedtls_pk_init( &((*pkey)->key) );
	if ( (ret = mbedtls_pk_setup( &((*pkey)->key), mbedtls_pk_info_from_type( MBEDTLS_PK_RSA ) )) != 0) {
		belle_sip_error("Certificate generation can't init pk_ctx: -%x", -ret);
		return -1;
	}
	if ( ( ret = mbedtls_rsa_gen_key( mbedtls_pk_rsa( (*pkey)->key ), mbedtls_ctr_drbg_random, &ctr_drbg, 3072, 65537 ) ) != 0) {
		belle_sip_error("Certificate generation can't generate rsa key: -%x", -ret);
		return -1;
	}

	/* if there is no path, don't write a file */
	if (path!=NULL) {
		mbedtls_pk_write_key_pem( &((*pkey)->key), (unsigned char *)file_buffer, 4096);
		file_buffer_len = strlen(file_buffer);
	}

	/* generate the certificate */
	mbedtls_x509write_crt_init( &crt );
	mbedtls_x509write_crt_set_md_alg( &crt, MBEDTLS_MD_SHA256 );

	mbedtls_mpi_init( &serial );

	if ( (ret = mbedtls_mpi_read_string( &serial, 10, "1" ) ) != 0 ) {
		belle_sip_error("Certificate generation can't read serial mpi: -%x", -ret);
		return -1;
	}

	mbedtls_x509write_crt_set_subject_key( &crt, &((*pkey)->key) );
	mbedtls_x509write_crt_set_issuer_key( &crt, &((*pkey)->key) );

	if ( (ret = mbedtls_x509write_crt_set_subject_name( &crt, formatted_subject) ) != 0) {
		belle_sip_error("Certificate generation can't set subject name: -%x", -ret);
		return -1;
	}

	if ( (ret = mbedtls_x509write_crt_set_issuer_name( &crt, formatted_subject) ) != 0) {
		belle_sip_error("Certificate generation can't set issuer name: -%x", -ret);
		return -1;
	}

	if ( (ret = mbedtls_x509write_crt_set_serial( &crt, &serial ) ) != 0) {
		belle_sip_error("Certificate generation can't set serial: -%x", -ret);
		return -1;
	}
	mbedtls_mpi_free(&serial);

	if ( (ret = mbedtls_x509write_crt_set_validity( &crt, "20010101000000", "20300101000000" ) ) != 0) {
		belle_sip_error("Certificate generation can't set validity: -%x", -ret);
		return -1;
	}

	/* store anyway certificate in pem format in a string even if we do not have file to write as we need it to get it in a mbedtls_x509_crt structure */
	if ( (ret = mbedtls_x509write_crt_pem( &crt, (unsigned char *)file_buffer+file_buffer_len, 4096, mbedtls_ctr_drbg_random, &ctr_drbg ) ) != 0) {
		belle_sip_error("Certificate generation can't write crt pem: -%x", -ret);
		return -1;
	}

	mbedtls_x509write_crt_free(&crt);

	// mbedtls 2.0 requires the buffer to contain the terminating NULL byte
	if ((ret = mbedtls_x509_crt_parse(&((*certificate)->cert), (unsigned char *)file_buffer, strlen(file_buffer) + 1)) != 0) {
		belle_sip_error("Certificate generation can't parse crt pem: -%x", -ret);
		return -1;
	}

	/* write the file if needed */
	if (path!=NULL) {
		name_with_path = (char *)belle_sip_malloc(strlen(path)+257); /* max filename is 256 bytes in dirent structure, +1 for / */
		path_length = strlen(path);
		memcpy(name_with_path, path, path_length);
		name_with_path[path_length] = '/';
		path_length++;
		memcpy(name_with_path+path_length, subject, strlen(subject));
		memcpy(name_with_path+path_length+strlen(subject), ".pem", 5);

		/* check if directory exists and if not, create it */
		belle_sip_mkdir(path);

		if ( (fd = fopen(name_with_path, "w") ) == NULL) {
			belle_sip_error("Certificate generation can't open/create file %s", name_with_path);
			free(name_with_path);
			belle_sip_object_unref(*pkey);
			belle_sip_object_unref(*certificate);
			*pkey = NULL;
			*certificate = NULL;
			return -1;
		}
		if ( fwrite(file_buffer, 1, strlen(file_buffer), fd) != strlen(file_buffer) ) {
			belle_sip_error("Certificate generation can't write into file %s", name_with_path);
			fclose(fd);
			belle_sip_object_unref(*pkey);
			belle_sip_object_unref(*certificate);
			*pkey = NULL;
			*certificate = NULL;
			free(name_with_path);
			return -1;
		}
		fclose(fd);
		free(name_with_path);
	}

	return 0;
}

/* Note : this code is duplicated in mediastreamer2/src/voip/dtls_srtp.c but get directly a mbedtls_x509_crt as input parameter */
char *belle_sip_certificates_chain_get_fingerprint(belle_sip_certificates_chain_t *certificate) {
	unsigned char buffer[64]={0}; /* buffer is max length of returned hash, which is 64 in case we use sha-512 */
	size_t hash_length = 0;
	const char *hash_alg_string=NULL;
	char *fingerprint = NULL;
	mbedtls_x509_crt *crt;
	if (certificate == NULL) return NULL;

	crt = &certificate->cert;
	/* fingerprint is a hash of the DER formated certificate (found in crt->raw.p) using the same hash function used by certificate signature */
	switch (crt->sig_md) {
		case MBEDTLS_MD_SHA1:
			mbedtls_sha1(crt->raw.p, crt->raw.len, buffer);
			hash_length = 20;
			hash_alg_string="SHA-1";
		break;

		case MBEDTLS_MD_SHA224:
			mbedtls_sha256(crt->raw.p, crt->raw.len, buffer, 1); /* last argument is a boolean, indicate to output sha-224 and not sha-256 */
			hash_length = 28;
			hash_alg_string="SHA-224";
		break;

		case MBEDTLS_MD_SHA256:
			mbedtls_sha256(crt->raw.p, crt->raw.len, buffer, 0);
			hash_length = 32;
			hash_alg_string="SHA-256";
		break;

		case MBEDTLS_MD_SHA384:
			mbedtls_sha512(crt->raw.p, crt->raw.len, buffer, 1); /* last argument is a boolean, indicate to output sha-384 and not sha-512 */
			hash_length = 48;
			hash_alg_string="SHA-384";
		break;

		case MBEDTLS_MD_SHA512:
			mbedtls_sha512(crt->raw.p, crt->raw.len, buffer, 1); /* last argument is a boolean, indicate to output sha-384 and not sha-512 */
			hash_length = 64;
			hash_alg_string="SHA-512";
		break;

		default:
			return NULL;
		break;
	}

	if (hash_length>0) {
		size_t i;
		int fingerprint_index = strlen(hash_alg_string);
		size_t size=fingerprint_index+3*hash_length+1;
		char prefix=' ';
		/* fingerprint will be : hash_alg_string+' '+HEX : separated values: length is strlen(hash_alg_string)+3*hash_lenght + 1 for null termination */
		fingerprint = belle_sip_malloc0(size);
		snprintf(fingerprint, size, "%s", hash_alg_string);
		for (i=0; i<hash_length; i++, fingerprint_index+=3) {
			snprintf((char*)fingerprint+fingerprint_index, size-fingerprint_index, "%c%02X", prefix,buffer[i]);
			prefix=':';
		}
		*(fingerprint+fingerprint_index) = '\0';
	}

	return fingerprint;
}

static void belle_sip_certificates_chain_destroy(belle_sip_certificates_chain_t *certificate){
	mbedtls_x509_crt_free(&certificate->cert);
}

static void belle_sip_certificates_chain_clone(belle_sip_certificates_chain_t *certificate, const belle_sip_certificates_chain_t *orig){
	belle_sip_error("belle_sip_certificate_clone not supported");
}

BELLE_SIP_DECLARE_NO_IMPLEMENTED_INTERFACES(belle_sip_certificates_chain_t);
BELLE_SIP_INSTANCIATE_VPTR(belle_sip_certificates_chain_t,belle_sip_object_t,belle_sip_certificates_chain_destroy,belle_sip_certificates_chain_clone,NULL,TRUE);




belle_sip_signing_key_t* belle_sip_signing_key_parse(const char* buff, size_t size,const char* passwd) {
	belle_sip_signing_key_t* signing_key = belle_sip_object_new(belle_sip_signing_key_t);
	int err;
	unsigned char *extended_buff = (unsigned char *)extend_buffer(buff, size);

	mbedtls_pk_init(&signing_key->key);
	/* for API v1.3 or greater also parses public keys other than RSA */
	err = mbedtls_pk_parse_key(&signing_key->key, extended_buff, size + 1,
			(const unsigned char *)passwd ,passwd ? strlen(passwd) : 0);
	belle_sip_free(extended_buff);

	/* make sure cipher is RSA to be consistent with API v1.2 */
	if(err==0 && !mbedtls_pk_can_do(&signing_key->key,MBEDTLS_PK_RSA))
	err=MBEDTLS_ERR_PK_TYPE_MISMATCH;
	if (err<0) {
		char tmp[128];
		mbedtls_strerror(err,tmp,sizeof(tmp));
		belle_sip_error("cannot parse public key because [%s]",tmp);
                mbedtls_pk_free(&signing_key->key);
		belle_sip_object_unref(signing_key);
		return NULL;
	}
	return signing_key;
}

belle_sip_signing_key_t* belle_sip_signing_key_parse_file(const char* path,const char* passwd) {
	belle_sip_signing_key_t* signing_key = belle_sip_object_new(belle_sip_signing_key_t);
	int err;
	mbedtls_pk_init(&signing_key->key);
	/* for API v1.3 or greater also parses public keys other than RSA */
	err=mbedtls_pk_parse_keyfile(&signing_key->key,path, passwd);
	/* make sure cipher is RSA to be consistent with API v1.2 */
	if(err==0 && !mbedtls_pk_can_do(&signing_key->key,MBEDTLS_PK_RSA))
	err=MBEDTLS_ERR_PK_TYPE_MISMATCH;
	if (err<0) {
		char tmp[128];
		mbedtls_strerror(err,tmp,sizeof(tmp));
		belle_sip_error("cannot parse public key because [%s]",tmp);
		mbedtls_pk_free(&signing_key->key);
		belle_sip_object_unref(signing_key);
		return NULL;
	}

	return signing_key;
}


static void belle_sip_signing_key_destroy(belle_sip_signing_key_t *signing_key){
	mbedtls_pk_free(&signing_key->key);
}

static void belle_sip_signing_key_clone(belle_sip_signing_key_t *signing_key, const belle_sip_signing_key_t *orig){
	belle_sip_error("belle_sip_signing_key_clone not supported");
}

BELLE_SIP_DECLARE_NO_IMPLEMENTED_INTERFACES(belle_sip_signing_key_t);
BELLE_SIP_INSTANCIATE_VPTR(belle_sip_signing_key_t,belle_sip_object_t,belle_sip_signing_key_destroy,belle_sip_signing_key_clone,NULL,TRUE);

	

	


