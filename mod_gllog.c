#include "httpd.h"
#include "http_config.h"
#include "apr_buckets.h"
#include "apr_general.h"
#include "apr_lib.h"
#include "apr_escape.h"
#include "apr_strings.h"
#include "util_filter.h"
#include "http_log.h"
#include "http_request.h"
#include "http_core.h"
#include "http_config.h"
#include "ap_config.h"
#include "ap_regex.h"
#include <ctype.h>
#include "openssl/bio.h"
#include "openssl/ssl.h"
#include "openssl/err.h"
#include <openssl/aes.h>
#include "http_protocol.h"

static const char *gl_cookie_regex = "^PLAY_SESSION=([A-Za-z0-9_]+)-sessionid=([A-Za-z0-9_]+)$";
static const char *gl_sessionstring_regex = "^([^\t]+)\t([a-z0-9-]+)$";

module AP_MODULE_DECLARE_DATA gllog_module;

typedef struct
{
    int bEnabled;
    const char *sKey;
    int bSignature;
} GlLogConfig;

typedef struct {
	const char *signature;		/* SHA1 HMAC */
	const char *sessionid;		/* Session token*/
} gl_play_token;

static void *GlLogCreateServerConfig(apr_pool_t *p, server_rec *s)
{
    GlLogConfig *pConfig = apr_pcalloc(p, sizeof *pConfig);

    pConfig->bEnabled = 0;
    pConfig->sKey = "";
    pConfig->bSignature = 0;

    return pConfig;
}

/**
Set notes for LogFormat.
*/
static void set_module_notes(request_rec *r, char *username, char *sessionid, char *validity) {
	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, 0, r->server, "Setting notes username: %s sessionid: %s validity: %s", username, sessionid, validity); 
	apr_table_set(r->notes, "gl_username", username);
	apr_table_set(r->notes, "gl_sessionid", sessionid);
	apr_table_set(r->notes, "gl_signaturevalid", validity);
}

/**
Checks the HMAC SHA1 signature. Returns 1 if valid.
*/
static int check_signature(request_rec *r, const char *signature, const char *sessionid) {
	GlLogConfig *pConfig = ap_get_module_config(r->server->module_config, &gllog_module);
	
	int result = 0;
	char *digest = apr_pcalloc(r->pool, 64);
	char *data = apr_psprintf(r->pool, "sessionid=%s", sessionid);
	unsigned int i = 64;

	HMAC(EVP_sha1(), pConfig->sKey, strlen(pConfig->sKey), (const unsigned char *)data, strlen(data), (unsigned char *)digest, &i);
	const char *hexdigest = apr_pescape_hex(r->pool, digest, i, 0);
	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, 0, r->server, "Generated signature %s, original %s", hexdigest, signature) ; 
	if (apr_strnatcmp(hexdigest, signature) == 0) {
		result = 1;
	}
	return result;
}

/**
Decrypt the play-graylog session cookie's sessionid part
*/
static char* decrypt_sessionid(const char *sessionid, request_rec *r) {
	GlLogConfig *pConfig = ap_get_module_config(r->server->module_config, &gllog_module);
	
	const char *session_binary;
	int session_binary_len;
	char *plaintext = NULL;

	// Initialize OpenSSL
	EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();
  	EVP_CIPHER_CTX_init(ctx);
  	EVP_CIPHER_CTX_set_padding(ctx, 1); // PKCS#5
  	
  	// Decode hex string to binary string
	session_binary = apr_punescape_hex(r->pool, sessionid, 0, NULL);
	if (session_binary == NULL) {
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0, r->server, "Unable to decode hex string!"); 
		goto cleanup;
	}
	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, 0, r->server, "Hex decoded: %s (len=%d)", session_binary, (int) strlen(session_binary)); 
	
	// Use max 16 characters for key!
	char *key;
	if (strlen(pConfig->sKey)<=16) {
		key = (char*) pConfig->sKey;
	} else {
		key = apr_pcalloc(r->pool, 17);
		apr_cpystrn (key, pConfig->sKey, 17);
	}
	// AES-128 ECB... 
	if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, (const unsigned char *)key, NULL)) {
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0, r->server, "Error initializing decryption"); 
		goto cleanup;
	}
	
	// Reserve space for plaintext
	session_binary_len = strlen(session_binary);
	plaintext = apr_pcalloc(r->pool, session_binary_len+1);
	
	// Decrypt
	int rounds = (session_binary_len/32)+ ((session_binary_len % 32)!=0);
	int decrypted = 0;	// Bytes decrypted every round
	int total = 0;		// Count the total bytes decrypted
	int x=0;
	while ( x < rounds ) {
		if(1 != EVP_DecryptUpdate(ctx, (unsigned char *)plaintext+(x*32), &decrypted, (const unsigned char *)session_binary+(x*32), 32)) {
			ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0, r->server, "Error in decryption"); 
			plaintext = NULL;
			goto cleanup;
		}
		x++;
		total += decrypted;
	}
	
	plaintext[total] = 0; // End the string at correct length
	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, 0, r->server, "Decrypted: %s (len=%d)", plaintext, (int) strlen(plaintext)); 
	
cleanup:
	EVP_CIPHER_CTX_free(ctx);
	return plaintext;
}

/**
Scan the request headers for the PLAY_SESSION cookie, and return it.
*/
static gl_play_token* get_session_token(request_rec *r) {
	gl_play_token *token = NULL;
	apr_table_entry_t *e = NULL;
	ap_regex_t *cpat = ap_pregcomp(r->pool, gl_cookie_regex, AP_REG_EXTENDED|AP_REG_ICASE);
	ap_regmatch_t pmatch[3];
	
	const apr_array_header_t *headers;
	int i = 0;
	
	headers = apr_table_elts(r->headers_in);
	e = (apr_table_entry_t*) headers->elts;
    for(i = 0; i < headers->nelts; i++) {
    	if (ap_regexec(cpat, e[i].val, cpat->re_nsub+1, pmatch, 0) == 0) {
    		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, 0, r->server, "Cookie sent by client: %s", e[i].val); 
    		token = apr_palloc(r->pool, sizeof(gl_play_token));
    		token->signature = ap_pregsub(r->pool, "$1", e[i].val, cpat->re_nsub+1, pmatch);
    		token->sessionid = ap_pregsub(r->pool, "$2", e[i].val, cpat->re_nsub+1, pmatch);
    		return token;
    	}
    }
    return NULL;
}

/**
Main handler for mod_gllog.
*/
static int gllog_handler(request_rec *r)
{
	GlLogConfig *pConfig = ap_get_module_config(r->server->module_config, &gllog_module);
    if (!pConfig->bEnabled)
        return DECLINED;
        
	ap_regex_t *cpat = ap_pregcomp(r->pool, gl_sessionstring_regex, AP_REG_EXTENDED|AP_REG_ICASE);
	ap_regmatch_t pmatch[3];
	char* sessionstring;
	char* username = "-";
	char* sessionid = "-";
	char* signaturestatus = "invalid";
	
	gl_play_token *token = get_session_token(r);
	if (token != NULL) {
		// Retrieve username & sessionid
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, 0, r->server, "Received signature: %s sessionid: %s", token->signature, token->sessionid ); 
		sessionstring = decrypt_sessionid(token->sessionid, r);
		if (sessionstring != NULL) {
			if (ap_regexec(cpat, sessionstring, cpat->re_nsub+1, pmatch, 0) == 0) {
				username = ap_pregsub(r->pool, "$1", sessionstring, cpat->re_nsub+1, pmatch);
				sessionid = ap_pregsub(r->pool, "$2", sessionstring, cpat->re_nsub+1, pmatch);
    		}
		}
		
		// Check the signature
		if (pConfig->bSignature) {
			if (check_signature(r, token->signature, token->sessionid) == 1) {
				signaturestatus = "valid";
			}
		} else {
			signaturestatus = "disabled";
		}
	}

	set_module_notes(r, username, sessionid, signaturestatus);
    
    return OK;
}

static const char *GlLogEnable(cmd_parms *cmd, void *dummy, int arg)
{
    GlLogConfig *pConfig
      = ap_get_module_config(cmd->server->module_config,
                             &gllog_module);
    pConfig->bEnabled=arg;

    return NULL;
}

static const char *GlLogKey(cmd_parms *cmd, void *dummy, const char *arg)
{
    GlLogConfig *pConfig
      = ap_get_module_config(cmd->server->module_config,
                             &gllog_module);
    pConfig->sKey=arg;

    return NULL;
}

static const char *GlLogSignature(cmd_parms *cmd, void *dummy, int arg)
{
    GlLogConfig *pConfig
      = ap_get_module_config(cmd->server->module_config,
                             &gllog_module);
    pConfig->bSignature=arg;

    return NULL;
}


static const command_rec GlLogCmds[] =
{
    AP_INIT_FLAG("GlLog", GlLogEnable, NULL, RSRC_CONF, "Enable or disable mod_gllog"),
    AP_INIT_TAKE1("GlLogKey", GlLogKey, NULL, RSRC_CONF, "Set the encryption key"),
    AP_INIT_FLAG("GlLogSignature", GlLogSignature, NULL, RSRC_CONF, "Verify the signature"),
    { NULL }
};
    
static void GlLogRegisterHooks(apr_pool_t *p)
{
    ap_hook_log_transaction(gllog_handler, NULL, NULL, APR_HOOK_FIRST);
}

AP_DECLARE_MODULE(gllog) =
{
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    GlLogCreateServerConfig,
    NULL,
    GlLogCmds,
    GlLogRegisterHooks
};

