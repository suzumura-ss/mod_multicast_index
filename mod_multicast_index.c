/* 
 * Copyright 2010 Toshiyuki Suzumura
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_request.h"
#include "http_log.h"
#include "ap_config.h"
#include "apr_lib.h"
#include "apr_strings.h"
#include "apr_tables.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#define MULTICAST_INDEX "X-Multicast-Index"
static const char VERSION[] = "mod_multicast_index/0.1";
static const char CONFIG_MULTICAST[] = MULTICAST_INDEX;
static const char X_INDEX_200[] = MULTICAST_INDEX "_200";
static const char X_INDEX_404[] = MULTICAST_INDEX "_404";
 
module AP_MODULE_DECLARE_DATA multicast_index_module;

#define AP_LOG_DEBUG(rec, fmt, ...) ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, rec, fmt, ##__VA_ARGS__)
#define AP_LOG_INFO(rec, fmt, ...) ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, rec, "[multicast_idx] " fmt, ##__VA_ARGS__)
#define AP_LOG_WARN(rec, fmt, ...) ap_log_rerror(APLOG_MARK, APLOG_WARNING,0, rec, "[multicast_idx] " fmt, ##__VA_ARGS__)
#define AP_LOG_ERR(rec, fmt, ...) ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, rec, "[multicast_idx] " fmt, ##__VA_ARGS__)


// Config store
typedef struct {
  struct sockaddr* addr;
  size_t  len;
} addr_in_t;

typedef struct {
  apr_pool_t* pool;
  int   enabled;
  addr_in_t multicast_interface;
  addr_in_t multicast_address;
} multicast_conf;


//
// Main functions.
//

static char* unescape_specialchars(apr_pool_t* pool, const char* str)
{
  char* p, *r = apr_pstrdup(pool, str);
  for(p=r; p[0]!='\0'; p++) {
    if((p[0]=='%') && (p[1]!='\0')) {
      switch(p[1]) {
      case 'r':
        p[0]='\r';  break;
      case 'n':
        p[0]='\n';  break;
      default:
        break;
      }
      memmove(p+1, p+2, strlen(p+1));
    }
  }
  return r;
}

// Multicast packet.
static apr_status_t multicast_packet(request_rec* rec, multicast_conf* conf, const char* _msg)
{
  int r, s = socket(AF_INET, SOCK_DGRAM, 0);
  char* msg = unescape_specialchars(rec->pool, _msg);

  AP_LOG_DEBUG(rec, "unescaped string: %s", msg);

  r = setsockopt(s, SOL_IP, IP_MULTICAST_IF, conf->multicast_interface.addr, conf->multicast_interface.len);
  if(r!=0) {
    r = errno;
    AP_LOG_ERR(rec, "setsockopt() failed - %s(%d)", strerror(r), r);
    goto FINALLY;
  }

  r = connect(s, conf->multicast_address.addr, conf->multicast_address.len);
  if(r!=0) {
    r = errno;
    AP_LOG_ERR(rec, "connect() failed - %s(%d)", strerror(r), r);
    goto FINALLY;
  }

  r = send(s, msg, strlen(msg), 0);
  r = (r>=0)? APR_SUCCESS: errno;

FINALLY:
  if(s>=0) {
    shutdown(s, SHUT_RDWR);
    close(s);
  }
  return r;
}

// Multicast "404 Not Found."
static apr_status_t multicast_404_not_found(request_rec* rec, multicast_conf* conf)
{
  const char* msg = apr_table_get(rec->headers_in, X_INDEX_404);
  if(msg==NULL) msg = apr_psprintf(rec->pool, "%s:%s Not found.\n", rec->hostname, rec->uri);
  return multicast_packet(rec, conf, msg);
}

// Multicast "200 OK."
static apr_status_t multicast_200_ok(request_rec* rec, multicast_conf* conf)
{
  const char* msg = apr_table_get(rec->headers_in, X_INDEX_200);
  if(msg==NULL) msg = apr_psprintf(rec->pool, "%s:%s Found.\n", rec->hostname, rec->uri);
  return multicast_packet(rec, conf, msg);
}


// Multicast index handler
static int multicast_index_handler(request_rec *rec)
{
  multicast_conf* conf = ap_get_module_config(rec->per_dir_config, &multicast_index_module);
  apr_status_t status = APR_SUCCESS;
  apr_finfo_t finfo;
  apr_dir_t* dir;

  if(strcasecmp(rec->handler, MULTICAST_INDEX)) return DECLINED;
  if(!conf || !conf->enabled) return DECLINED;
  if(rec->method_number!=M_GET) return DECLINED;

  // setup content-type of response.
  rec->content_type = "text/json";

  // do request
  status = apr_dir_open(&dir, rec->filename, rec->pool);
  if(status!=APR_SUCCESS) {
    // 404 Not Found.
    rec->status = HTTP_NOT_FOUND;
    return multicast_404_not_found(rec, conf);
  }

  // 200 OK.
  if(!rec->header_only) {
    int the_first = TRUE;
    ap_rputs("[", rec);
    while((status=apr_dir_read(&finfo, APR_FINFO_NAME|APR_FINFO_TYPE, dir))==APR_SUCCESS) {
      if((strcmp(finfo.name, ".")==0) || (strcmp(finfo.name, "..")==0)) continue;
      if(the_first) { the_first = FALSE; } else { ap_rputs(",", rec); }
      switch(finfo.filetype) {
      case APR_DIR:
        ap_rprintf(rec, "\"%s/\"", finfo.name);
        break;
      case APR_REG:
        ap_rprintf(rec, "\"%s\"", finfo.name);
        break;
      case APR_LNK:
        ap_rprintf(rec, "\"%s@\"", finfo.name);
        break;
      default:
        break;
      }
    }
    ap_rputs("]\n", rec);
    rec->status = HTTP_OK;
  }
  apr_dir_close(dir);

  return multicast_200_ok(rec, conf);
}


//
// Configurators, and Register.
//
static void* config_create(apr_pool_t* p, char* path)
{
  multicast_conf* conf = apr_palloc(p, sizeof(multicast_conf));
  memset(conf, 0, sizeof(conf));
  conf->pool = p;
  conf->enabled = FALSE;
  return conf;
}

// string to addr_in
static const char* string_to_addr_in(apr_pool_t* p, const char* param, const char* port, addr_in_t* addr_in)
{
  struct addrinfo hints, *result;
  int r;

  memset(&hints, 0, sizeof(hints));
  hints.ai_flags = 0;
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_protocol = 0;
  hints.ai_canonname = NULL;
  hints.ai_addr = NULL;
  hints.ai_next = NULL;

  r = getaddrinfo(param, port, &hints, &result);
  if(r!=0) return "getaddrinfo() failed.";

  addr_in->addr = apr_pmemdup(p, result->ai_addr, result->ai_addrlen);
  addr_in->len = result->ai_addrlen;
  freeaddrinfo(result);
  return NULL;
}

static const char* config_address_slot(cmd_parms* cmd, void* _conf, \
                      const char* param1, const char* param2, const char* param3)
{
  const char* r;
  multicast_conf* conf = _conf;
  r = string_to_addr_in(conf->pool, param1, NULL, &(conf->multicast_interface));
  if(r==NULL) {
    r = string_to_addr_in(conf->pool, param2, param3, &(conf->multicast_address));
  }
  conf->enabled = (r==NULL)? TRUE: FALSE;

  return r;
}

static const command_rec config_cmds[] = {
  AP_INIT_TAKE3(CONFIG_MULTICAST, config_address_slot, NULL, OR_OPTIONS, "Multicast options."),
  { NULL },
};

static void multicast_index_register_hooks(apr_pool_t *p)
{
  ap_hook_handler(multicast_index_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

// Dispatch list for API hooks.
module AP_MODULE_DECLARE_DATA multicast_index_module = {
  STANDARD20_MODULE_STUFF, 
  config_create,    // create per-dir    config structures
  NULL,             // merge  per-dir    config structures
  NULL,             // create per-server config structures
  NULL,             // merge  per-server config structures
  config_cmds,      // table of config file commands
  multicast_index_register_hooks  // register hooks
};

