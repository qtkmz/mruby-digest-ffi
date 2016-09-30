#include <mruby.h>
#include <mruby/variable.h>
#include <mruby/class.h>
#include <mruby/string.h>
#include <mruby/data.h>
#include <sys/types.h>
#include <dlfcn.h>
#include <ffi.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/*---------------------------------------------------------------------------*/
#define MD5_LBLOCK 16
#define RIPEMD160_LBLOCK  256
#define SHA_LBLOCK 16
#define SHA512_CBLOCK (SHA_LBLOCK*8)

typedef unsigned long MD5_LONG;
typedef unsigned long RIPEMD160_LONG;
typedef unsigned long SHA_LONG;
typedef unsigned long long SHA_LONG64;

typedef struct {
  MD5_LONG A,B,C,D;
  MD5_LONG Nl,Nh;
  MD5_LONG data[MD5_LBLOCK];
  unsigned int num;
} MD5_CTX;

typedef struct {
  RIPEMD160_LONG A,B,C,D,E;
  RIPEMD160_LONG Nl,Nh;
  RIPEMD160_LONG data[RIPEMD160_LBLOCK];
  unsigned int   num;
} RIPEMD160_CTX;

typedef struct {
  SHA_LONG h0,h1,h2,h3,h4;
  SHA_LONG Nl,Nh;
  SHA_LONG data[SHA_LBLOCK];
  unsigned int num;
} SHA_CTX;

typedef struct {
  SHA_LONG h[8];
  SHA_LONG Nl,Nh;
  SHA_LONG data[SHA_LBLOCK];
  unsigned int num,md_len;
} SHA256_CTX;

typedef struct {
  SHA_LONG64 h[8];
  SHA_LONG64 Nl,Nh;
  union {
    SHA_LONG64 d[SHA_LBLOCK];
    unsigned char p[SHA512_CBLOCK];
  } u;
  unsigned int num,md_len;
} SHA512_CTX;

/*---------------------------------------------------------------------------*/
#define HMAC_MAX_MD_CBLOCK      128

typedef struct {
  void *digest;
  void *engine;
  unsigned long flags;
  void *md_data;
  void *pctx;
  void *update;
} EVP_MD_CTX;

typedef struct {
  void *md;
  EVP_MD_CTX md_ctx;
  EVP_MD_CTX i_ctx;
  EVP_MD_CTX o_ctx;
  unsigned int key_length;
  unsigned char key[HMAC_MAX_MD_CBLOCK];
} HMAC_CTX;
/*---------------------------------------------------------------------------*/

typedef enum {
  MRB_DIHEST,
  MRB_HMAC
} mrb_digest_t;

typedef struct {
  const char *name;
  size_t block_size;
  size_t digest_size;

  const char *init_func_name;
  const char *update_func_name;
  const char *final_func_name;

  size_t ctx_size;
} mrb_digest_conf;

typedef struct {
  void *ctx;
  size_t ctx_size;
  size_t block_size;
  size_t digest_size;

  void *handle;
  void *func_init;
  void *func_update;
  void *func_final;
} mrb_digest;

#define MRB_DIGEST_AVAILABLE_SIZ    128  // md5=16, sha1=20, sha512=64
#define MRB_HEXDIGEST_AVAILABLE_SIZ 256

static mrb_digest_conf conf[] = {
  { "Digest::MD5", 64, 16, "MD5_Init", "MD5_Update", "MD5_Final", sizeof(MD5_CTX) },
  { "Digest::RMD160", 64, 20, "RIPEMD160_Init", "RIPEMD160_Update", "RIPEMD160_Final", sizeof(RIPEMD160_CTX) },
  { "Digest::SHA1", 64, 20, "SHA1_Init", "SHA1_Update", "SHA1_Final", sizeof(SHA_CTX) },
  { "Digest::SHA256", 64, 32, "SHA256_Init", "SHA256_Update", "SHA256_Final", sizeof(SHA256_CTX) },
  { "Digest::SHA384", 128, 48, "SHA384_Init", "SHA384_Update", "SHA384_Final", sizeof(SHA512_CTX) },
  { "Digest::SHA512", 128, 64, "SHA512_Init", "SHA512_Update", "SHA512_Final", sizeof(SHA512_CTX) },
  { "Digest::HMAC", 0, 0, "HMAC_CTX_init", "HMAC_Update", "HMAC_Final", sizeof(HMAC_CTX) }
};

static mrb_value mrb_digest_block_length(mrb_state *mrb, mrb_value self);
static mrb_value mrb_digest_update(mrb_state *mrb, mrb_value self);
static mrb_value mrb_digest_digest(mrb_state *mrb, mrb_value self);
static mrb_value mrb_digest_digest_length(mrb_state *mrb, mrb_value self);
static mrb_value mrb_digest_hmac_block_length(mrb_state *mrb, mrb_value self);
static mrb_value mrb_digest_hmac_update(mrb_state *mrb, mrb_value self);
static mrb_value mrb_digest_hmac_digest(mrb_state *mrb, mrb_value self);
static mrb_value mrb_digest_hmac_digest_length(mrb_state *mrb, mrb_value self);
static mrb_value mrb_digest_hexdigest(mrb_state *mrb, mrb_value self);
static mrb_value mrb_digest_hmac_hexdigest(mrb_state *mrb, mrb_value self);
static void mrb_digest_free(mrb_state *mrb, void *p);
static void mrb_hmac_free(mrb_state *mrb, void *p);

static mrb_digest_conf* get_digest_conf(const char *class_name);
static mrb_digest* init(mrb_state *mrb, mrb_value self);
static mrb_digest* alloc_instance_data(mrb_state *mrb, size_t ctx_size);

static void call_init(mrb_state *mrb, void (*fn)(void), void *ctx);
static void call_update(mrb_state *mrb, void (*fn)(void), void *ctx, unsigned char *s, size_t len);
static void call_final(mrb_state *mrb, void (*fn)(void), void *ctx, unsigned char *md);
static void* call_digester(mrb_state *mrb, void (*fn)(void));
static void call_hmac_init_ex(mrb_state *mrb, void (*fn)(void), void *ctx, unsigned char *s, size_t len, void (*evp_func)(void), void *engine);
static void call_hmac_final(mrb_state *mrb, void (*fn)(void), void *ctx, unsigned char *s, size_t *len);

static char* digest2hex(char *hex, unsigned char *digest, size_t digest_size);

static mrb_value mrb_md5_init(mrb_state *mrb, mrb_value self);
static mrb_value mrb_rmd160_init(mrb_state *mrb, mrb_value self);
static mrb_value mrb_sha1_init(mrb_state *mrb, mrb_value self);
static mrb_value mrb_sha256_init(mrb_state *mrb, mrb_value self);
static mrb_value mrb_sha384_init(mrb_state *mrb, mrb_value self);
static mrb_value mrb_sha512_init(mrb_state *mrb, mrb_value self);
static mrb_value mrb_hmac_init(mrb_state *mrb, mrb_value self);

static void* get_hmac_init_ex_func(mrb_state *mrb, mrb_digest *digest);
static void* get_hmac_cleanup_func(mrb_state *mrb, mrb_digest *digest);
static void* get_evp_md_func(mrb_state *mrb, mrb_digest *digest, const char *name);

static const mrb_data_type mrb_digest_type = {
  "mrb_digest_ffi", mrb_digest_free,
};

static const mrb_data_type mrb_hmac_type = {
  "mrb_digest_hmac_ffi", mrb_hmac_free,
};

static mrb_value
mrb_digest_block_length(mrb_state *mrb, mrb_value self) {
  mrb_digest *digest;

  digest = mrb_get_datatype(mrb, self, &mrb_digest_type);
  if (digest == NULL) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  return mrb_fixnum_value(digest->block_size);
}

static mrb_value
mrb_digest_update(mrb_state *mrb, mrb_value self) {
  mrb_digest *digest;
  unsigned char *s;
  mrb_int len;

  mrb_get_args(mrb, "s", &s, &len);

  digest = mrb_get_datatype(mrb, self, &mrb_digest_type);
  if (digest == NULL) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  call_update(mrb, FFI_FN(digest->func_update), digest->ctx, s, len);

  return self;
}

static mrb_value
mrb_digest_digest(mrb_state *mrb, mrb_value self) {
  mrb_digest *digest;
  void *ctx_tmp;
  unsigned char md[MRB_DIGEST_AVAILABLE_SIZ];

  digest = mrb_get_datatype(mrb, self, &mrb_digest_type);
  if (digest == NULL) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  ctx_tmp = malloc(digest->ctx_size);
  if (ctx_tmp == NULL) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "cannot allocate memory");
  }
  memcpy(ctx_tmp, digest->ctx, digest->ctx_size);

  call_final(mrb, FFI_FN(digest->func_final), ctx_tmp, md);

  free(ctx_tmp);

  return mrb_str_new(mrb, (char *)md, digest->digest_size);
}

static mrb_value mrb_digest_digest_length(mrb_state *mrb, mrb_value self) {
  mrb_digest *digest;

  digest = mrb_get_datatype(mrb, self, &mrb_digest_type);
  if (digest == NULL) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  return mrb_fixnum_value(digest->digest_size);
}

static mrb_value
mrb_digest_hmac_block_length(mrb_state *mrb, mrb_value self) {
  mrb_digest *digest;

  digest = mrb_get_datatype(mrb, self, &mrb_hmac_type);
  if (digest == NULL) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  return mrb_fixnum_value(digest->block_size);
}

static mrb_value
mrb_digest_hmac_update(mrb_state *mrb, mrb_value self) {
  mrb_digest *digest;
  unsigned char *s;
  mrb_int len;

  mrb_get_args(mrb, "s", &s, &len);

  digest = mrb_get_datatype(mrb, self, &mrb_hmac_type);
  if (digest == NULL) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  call_update(mrb, FFI_FN(digest->func_update), digest->ctx, s, len);

  return self;
}

static mrb_value
mrb_digest_hmac_digest(mrb_state *mrb, mrb_value self) {
  mrb_digest *digest;
  void *ctx_tmp;
  unsigned char md[MRB_DIGEST_AVAILABLE_SIZ];
  size_t md_len;

  digest = mrb_get_datatype(mrb, self, &mrb_hmac_type);
  if (digest == NULL) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  ctx_tmp = malloc(digest->ctx_size);
  if (ctx_tmp == NULL) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "cannot allocate memory");
  }
  memcpy(ctx_tmp, digest->ctx, digest->ctx_size);

  md_len = 0L;
  call_hmac_final(mrb, FFI_FN(digest->func_final), ctx_tmp, md, &md_len);

  free(ctx_tmp);

  return mrb_str_new(mrb, (char *)md, md_len);
}

static mrb_value
mrb_digest_hmac_digest_length(mrb_state *mrb, mrb_value self) {
  mrb_digest *digest;

  digest = mrb_get_datatype(mrb, self, &mrb_hmac_type);
  if (digest == NULL) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  return mrb_fixnum_value(digest->digest_size);
}

static mrb_value
mrb_digest_hexdigest(mrb_state *mrb, mrb_value self) {
  mrb_digest *digest;
  void *ctx_tmp;
  unsigned char md[MRB_DIGEST_AVAILABLE_SIZ];
  char hex[MRB_HEXDIGEST_AVAILABLE_SIZ];

  digest = mrb_get_datatype(mrb, self, &mrb_digest_type);
  if (digest == NULL) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  ctx_tmp = malloc(digest->ctx_size);
  if (ctx_tmp == NULL) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "cannot allocate memory");
  }
  memcpy(ctx_tmp, digest->ctx, digest->ctx_size);

  call_final(mrb, FFI_FN(digest->func_final), ctx_tmp, md);

  free(ctx_tmp);

  return mrb_str_new(mrb, (const char *)digest2hex(hex, md, digest->digest_size), digest->digest_size * 2);
}

static mrb_value
mrb_digest_hmac_hexdigest(mrb_state *mrb, mrb_value self) {
  mrb_digest *digest;
  void *ctx_tmp;
  unsigned char md[MRB_DIGEST_AVAILABLE_SIZ];
  size_t md_len;
  char hex[MRB_HEXDIGEST_AVAILABLE_SIZ];

  digest = mrb_get_datatype(mrb, self, &mrb_hmac_type);
  if (digest == NULL) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  ctx_tmp = malloc(digest->ctx_size);
  if (ctx_tmp == NULL) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "cannot allocate memory");
  }
  memcpy(ctx_tmp, digest->ctx, digest->ctx_size);

  md_len = 0L;
  call_hmac_final(mrb, FFI_FN(digest->func_final), ctx_tmp, md, &md_len);

  free(ctx_tmp);

  return mrb_str_new(mrb, (const char *)digest2hex(hex, md, md_len), md_len * 2);
}

static void
mrb_digest_free(mrb_state *mrb, void *p) {
  mrb_digest *digest = (mrb_digest *)p;

  if (digest->handle != NULL) {
    dlclose(digest->handle);
  }

  free(digest->ctx);
  free(digest);
}

static void
mrb_hmac_free(mrb_state *mrb, void *p) {
  void *hmac_cleanup;
  mrb_digest *digest = (mrb_digest *)p;

  hmac_cleanup = get_hmac_cleanup_func(mrb, digest);

  call_init(mrb, FFI_FN(hmac_cleanup), digest->ctx);

  if (digest->handle != NULL) {
    dlclose(digest->handle);
  }

  free(digest->ctx);
  free(digest);
}

static mrb_digest_conf*
get_digest_conf(const char *class_name)
{
  int i;

  for (i = 0; i < (sizeof(conf) / sizeof(conf[0])); i++) {
    if (strcmp(class_name, conf[i].name) == 0) {
      return &conf[i];
    }
  }

  return NULL;
}

static mrb_digest*
init(mrb_state *mrb, mrb_value self) {
  mrb_digest *digest;
  char *err_msg;
  mrb_digest_conf *c;

  c = get_digest_conf(mrb_obj_classname(mrb, self));
  if (c == NULL) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  digest = alloc_instance_data(mrb, c->ctx_size);
  digest->block_size = c->block_size;
  digest->digest_size = c->digest_size;

  digest->handle = dlopen("libcrypto.so", RTLD_LAZY);
  if (digest->handle == NULL) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "cannot find library");
  }
  dlerror();

  digest->func_init = dlsym(digest->handle, c->init_func_name);
  if ((err_msg = dlerror()) != NULL)  {
    mrb_raise(mrb, E_RUNTIME_ERROR, "cannot find function");
  }
  dlerror();

  digest->func_update = dlsym(digest->handle, c->update_func_name);
  if ((err_msg = dlerror()) != NULL)  {
    mrb_raise(mrb, E_RUNTIME_ERROR, "cannot find function");
  }
  dlerror();

  digest->func_final = dlsym(digest->handle, c->final_func_name);
  if ((err_msg = dlerror()) != NULL)  {
    mrb_raise(mrb, E_RUNTIME_ERROR, "cannot find function");
  }
  dlerror();

  call_init(mrb, FFI_FN(digest->func_init), digest->ctx);

  return digest;
}

static mrb_digest*
alloc_instance_data(mrb_state *mrb, size_t ctx_size)
{
  mrb_digest *data;

  data = (mrb_digest *)malloc(sizeof(mrb_digest));
  if (data == NULL) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "cannot allocate memory");
  }

  data->ctx = malloc(ctx_size);
  if (data->ctx == NULL) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "cannot allocate memory");
  }

  data->ctx_size = ctx_size;

  return data;
}

static void
call_init(mrb_state *mrb, void (*fn)(void), void *ctx) {
  ffi_cif cif;
  ffi_type *args[1];
  void *values[1];
  int rc;
  void *c;

  args[0] = &ffi_type_pointer;

  if (ffi_prep_cif(&cif, FFI_DEFAULT_ABI, 1, &ffi_type_uint, args) != FFI_OK) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "cannot execute function");
  }

  c = ctx;

  values[0] = &c;

  ffi_call(&cif, fn, &rc, values);
}

static void
call_update(mrb_state *mrb, void (*fn)(void), void *ctx, unsigned char *s, size_t len) {
  ffi_cif cif;
  ffi_type *args[3];
  void *values[3];
  int rc;

  void *c;
  unsigned char *d;
  size_t l;

  args[0] = &ffi_type_pointer;
  args[1] = &ffi_type_pointer;
  args[2] = &ffi_type_uint64;

  if (ffi_prep_cif(&cif, FFI_DEFAULT_ABI, 3, &ffi_type_uint, args) != FFI_OK) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "cannot execute function");
  }

  c = ctx;
  d = s;
  l = len;

  values[0] = &c;
  values[1] = &d;
  values[2] = &l;

  ffi_call(&cif, fn, &rc, values);
}

static void
call_final(mrb_state *mrb, void (*fn)(void), void *ctx, unsigned char *md) {
  ffi_cif cif;
  ffi_type *args[2];
  void *values[2];
  int rc;

  void *c;
  unsigned char *m;

  args[0] = &ffi_type_pointer;
  args[1] = &ffi_type_pointer;

  if (ffi_prep_cif(&cif, FFI_DEFAULT_ABI, 2, &ffi_type_uint, args) != FFI_OK) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "cannot execute function");
  }

  c = ctx;
  m = md;

  values[0] = &m;
  values[1] = &c;

  ffi_call(&cif, fn, &rc, values);
}

static void*
call_digester(mrb_state *mrb, void (*fn)(void)) {
  ffi_cif cif;
  void *rc;

  if (ffi_prep_cif(&cif, FFI_DEFAULT_ABI, 0, &ffi_type_pointer, NULL) != FFI_OK) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "cannot execute function");
  }

  ffi_call(&cif, fn, &rc, NULL);

  return rc;
}

static void
call_hmac_init_ex(mrb_state *mrb, void (*fn)(void), void *ctx, unsigned char *s, size_t len, void (*evp_func)(void), void *engine) {
  ffi_cif cif;
  ffi_type *args[5];
  void *values[5];
  int rc;

  void *c;
  unsigned char *d;
  size_t l;
  void *f;
  void *e;

  args[0] = &ffi_type_pointer;
  args[1] = &ffi_type_pointer;
  args[2] = &ffi_type_uint64;
  args[3] = &ffi_type_pointer;
  args[4] = &ffi_type_pointer;

  if (ffi_prep_cif(&cif, FFI_DEFAULT_ABI, 5, &ffi_type_uint, args) != FFI_OK) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "cannot execute function");
  }

  c = ctx;
  d = s;
  l = len;
  f = evp_func;
  e = engine;

  values[0] = &c;
  values[1] = &d;
  values[2] = &l;
  values[3] = &f;
  values[4] = &e;

  ffi_call(&cif, fn, &rc, values);
}

static void
call_hmac_final(mrb_state *mrb, void (*fn)(void), void *ctx, unsigned char *s, size_t *len) {
  ffi_cif cif;
  ffi_type *args[3];
  void *values[3];
  int rc;

  void *c;
  unsigned char *d;
  size_t *l;

  args[0] = &ffi_type_pointer;
  args[1] = &ffi_type_pointer;
  args[2] = &ffi_type_pointer;

  if (ffi_prep_cif(&cif, FFI_DEFAULT_ABI, 3, &ffi_type_uint, args) != FFI_OK) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "cannot execute function");
  }

  c = ctx;
  d = s;
  l = len;

  values[0] = &c;
  values[1] = &d;
  values[2] = &l;

  ffi_call(&cif, fn, &rc, values);
}

static char*
digest2hex(char *hex, unsigned char *digest, size_t digest_size) {
  int i;
  for (i = 0; i < digest_size; i++) {
    sprintf(hex + (i * 2), "%02x", digest[i]);
  }
  return hex;
}

static mrb_value
mrb_md5_init(mrb_state *mrb, mrb_value self) {
  mrb_digest *digest = init(mrb, self);

  DATA_PTR(self) = digest;
  DATA_TYPE(self) = &mrb_digest_type;

  return self;
}

static mrb_value
mrb_rmd160_init(mrb_state *mrb, mrb_value self) {
  mrb_digest *digest = init(mrb, self);

  DATA_PTR(self) = digest;
  DATA_TYPE(self) = &mrb_digest_type;

  return self;
}

static mrb_value
mrb_sha1_init(mrb_state *mrb, mrb_value self) {
  mrb_digest *digest = init(mrb, self);

  DATA_PTR(self) = digest;
  DATA_TYPE(self) = &mrb_digest_type;

  return self;
}

static mrb_value
mrb_sha256_init(mrb_state *mrb, mrb_value self) {
  mrb_digest *digest = init(mrb, self);

  DATA_PTR(self) = digest;
  DATA_TYPE(self) = &mrb_digest_type;

  return self;
}

static mrb_value
mrb_sha384_init(mrb_state *mrb, mrb_value self) {
  mrb_digest *digest = init(mrb, self);

  DATA_PTR(self) = digest;
  DATA_TYPE(self) = &mrb_digest_type;

  return self;
}

static mrb_value
mrb_sha512_init(mrb_state *mrb, mrb_value self) {
  mrb_digest *digest = init(mrb, self);

  DATA_PTR(self) = digest;
  DATA_TYPE(self) = &mrb_digest_type;

  return self;
}

static mrb_value
mrb_hmac_init(mrb_state *mrb, mrb_value self) {
  unsigned char *s;
  mrb_int len;
  mrb_value digester;
  mrb_value r;
  void *evp_func;
  mrb_digest *digest;
  void *hmac_init_ex;
  void *evp_md;
  mrb_digest_conf *c;

  digest = init(mrb, self);

  mrb_get_args(mrb, "so", &s, &len, &digester);

  r = mrb_funcall(mrb, digester, "to_s", 0);
  evp_func = get_evp_md_func(mrb, digest, RSTRING_PTR(r));

  c = get_digest_conf(RSTRING_PTR(r));
  if (c == NULL) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }
  digest->block_size = c->block_size;
  digest->digest_size = c->digest_size;

  evp_md = call_digester(mrb, FFI_FN(evp_func));

  hmac_init_ex = get_hmac_init_ex_func(mrb, digest);

  call_hmac_init_ex(mrb, FFI_FN(hmac_init_ex), digest->ctx, s, len, evp_md, NULL);

  digest->handle = dlopen("libcrypto.so", RTLD_LAZY);

  DATA_PTR(self) = digest;
  DATA_TYPE(self) = &mrb_hmac_type;

  return self;
}

static void*
get_hmac_init_ex_func(mrb_state *mrb, mrb_digest *digest) {
  void *func;
  char *err_msg;

  func = dlsym(digest->handle, "HMAC_Init_ex");
  if ((err_msg = dlerror()) != NULL)  {
    mrb_raise(mrb, E_RUNTIME_ERROR, "cannot find function");
  }
  dlerror();

  return func;
}

static void*
get_hmac_cleanup_func(mrb_state *mrb, mrb_digest *digest) {
  void *func;
  char *err_msg;

  func = dlsym(digest->handle, "HMAC_CTX_cleanup");
  if ((err_msg = dlerror()) != NULL)  {
    mrb_raise(mrb, E_RUNTIME_ERROR, "cannot find function");
  }
  dlerror();

  return func;
}

static void *
get_evp_md_func(mrb_state *mrb, mrb_digest *digest, const char *name) {
  void *func;
  const char *func_name;
  char *err_msg;

  if (strcasecmp(name, "Digest::MD5") == 0) {
    func_name = "EVP_md5";
  } else if (strcasecmp(name, "Digest::RMD160") == 0) {
    func_name = "EVP_ripemd160";
  } else if (strcasecmp(name, "Digest::SHA1") == 0) {
    func_name = "EVP_sha1";
  } else if (strcasecmp(name, "Digest::SHA256") == 0) {
    func_name = "EVP_sha256";
  } else if (strcasecmp(name, "Digest::SHA384") == 0) {
    func_name = "EVP_sha384";
  } else if (strcasecmp(name, "Digest::SHA512") == 0) {
    func_name = "EVP_sha512";
  } else {
    mrb_raise(mrb, E_RUNTIME_ERROR, "cannot find function");
  }

  func = dlsym(digest->handle, func_name);
  if ((err_msg = dlerror()) != NULL)  {
    mrb_raise(mrb, E_RUNTIME_ERROR, "cannot find function");
  }
  dlerror();

  return func;
}

void
mrb_mruby_digest_ffi_gem_init(mrb_state* mrb) {
  struct RClass *digest;
  struct RClass *md5;
  struct RClass *rmd160;
  struct RClass *sha1;
  struct RClass *sha256;
  struct RClass *sha384;
  struct RClass *sha512;
  struct RClass *hmac;

  digest = mrb_define_module(mrb, "Digest");

  md5 = mrb_define_class_under(mrb, digest, "MD5", mrb->object_class);
  rmd160 = mrb_define_class_under(mrb, digest, "RMD160", mrb->object_class);
  sha1 = mrb_define_class_under(mrb, digest, "SHA1", mrb->object_class);
  sha256 = mrb_define_class_under(mrb, digest, "SHA256", mrb->object_class);
  sha384 = mrb_define_class_under(mrb, digest, "SHA384", mrb->object_class);
  sha512 = mrb_define_class_under(mrb, digest, "SHA512", mrb->object_class);

  MRB_SET_INSTANCE_TT(md5, MRB_TT_DATA);
  mrb_define_method(mrb, md5, "initialize", mrb_md5_init, MRB_ARGS_NONE());
  mrb_define_method(mrb, md5, "block_length", mrb_digest_block_length, MRB_ARGS_NONE());
  mrb_define_method(mrb, md5, "update", mrb_digest_update, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, md5, "digest", mrb_digest_digest, MRB_ARGS_NONE());
  mrb_define_method(mrb, md5, "digest_length", mrb_digest_digest_length, MRB_ARGS_NONE());
  mrb_define_method(mrb, md5, "hexdigest", mrb_digest_hexdigest, MRB_ARGS_NONE());

  MRB_SET_INSTANCE_TT(rmd160, MRB_TT_DATA);
  mrb_define_method(mrb, rmd160, "initialize", mrb_rmd160_init, MRB_ARGS_NONE());
  mrb_define_method(mrb, rmd160, "block_length", mrb_digest_block_length, MRB_ARGS_NONE());
  mrb_define_method(mrb, rmd160, "update", mrb_digest_update, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, rmd160, "digest", mrb_digest_digest, MRB_ARGS_NONE());
  mrb_define_method(mrb, rmd160, "digest_length", mrb_digest_digest_length, MRB_ARGS_NONE());
  mrb_define_method(mrb, rmd160, "hexdigest", mrb_digest_hexdigest, MRB_ARGS_NONE());

  MRB_SET_INSTANCE_TT(sha1, MRB_TT_DATA);
  mrb_define_method(mrb, sha1, "initialize", mrb_sha1_init, MRB_ARGS_NONE());
  mrb_define_method(mrb, sha1, "block_length", mrb_digest_block_length, MRB_ARGS_NONE());
  mrb_define_method(mrb, sha1, "update", mrb_digest_update, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, sha1, "digest", mrb_digest_digest, MRB_ARGS_NONE());
  mrb_define_method(mrb, sha1, "digest_length", mrb_digest_digest_length, MRB_ARGS_NONE());
  mrb_define_method(mrb, sha1, "hexdigest", mrb_digest_hexdigest, MRB_ARGS_NONE());

  MRB_SET_INSTANCE_TT(sha256, MRB_TT_DATA);
  mrb_define_method(mrb, sha256, "initialize", mrb_sha256_init, MRB_ARGS_NONE());
  mrb_define_method(mrb, sha256, "block_length", mrb_digest_block_length, MRB_ARGS_NONE());
  mrb_define_method(mrb, sha256, "update", mrb_digest_update, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, sha256, "digest", mrb_digest_digest, MRB_ARGS_NONE());
  mrb_define_method(mrb, sha256, "digest_length", mrb_digest_digest_length, MRB_ARGS_NONE());
  mrb_define_method(mrb, sha256, "hexdigest", mrb_digest_hexdigest, MRB_ARGS_NONE());

  MRB_SET_INSTANCE_TT(sha384, MRB_TT_DATA);
  mrb_define_method(mrb, sha384, "initialize", mrb_sha384_init, MRB_ARGS_NONE());
  mrb_define_method(mrb, sha384, "block_length", mrb_digest_block_length, MRB_ARGS_NONE());
  mrb_define_method(mrb, sha384, "update", mrb_digest_update, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, sha384, "digest", mrb_digest_digest, MRB_ARGS_NONE());
  mrb_define_method(mrb, sha384, "digest_length", mrb_digest_digest_length, MRB_ARGS_NONE());
  mrb_define_method(mrb, sha384, "hexdigest", mrb_digest_hexdigest, MRB_ARGS_NONE());

  MRB_SET_INSTANCE_TT(sha512, MRB_TT_DATA);
  mrb_define_method(mrb, sha512, "initialize", mrb_sha512_init, MRB_ARGS_NONE());
  mrb_define_method(mrb, sha512, "block_length", mrb_digest_block_length, MRB_ARGS_NONE());
  mrb_define_method(mrb, sha512, "update", mrb_digest_update, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, sha512, "digest", mrb_digest_digest, MRB_ARGS_NONE());
  mrb_define_method(mrb, sha512, "digest_length", mrb_digest_digest_length, MRB_ARGS_NONE());
  mrb_define_method(mrb, sha512, "hexdigest", mrb_digest_hexdigest, MRB_ARGS_NONE());

  hmac = mrb_define_class_under(mrb, digest, "HMAC", mrb->object_class);

  MRB_SET_INSTANCE_TT(hmac, MRB_TT_DATA);
  mrb_define_method(mrb, hmac, "initialize", mrb_hmac_init, MRB_ARGS_REQ(2));
  mrb_define_method(mrb, hmac, "block_length", mrb_digest_hmac_block_length, MRB_ARGS_NONE());
  mrb_define_method(mrb, hmac, "update", mrb_digest_hmac_update, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, hmac, "digest", mrb_digest_hmac_digest, MRB_ARGS_NONE());
  mrb_define_method(mrb, hmac, "digest_length", mrb_digest_hmac_digest_length, MRB_ARGS_NONE());
  mrb_define_method(mrb, hmac, "hexdigest", mrb_digest_hmac_hexdigest, MRB_ARGS_NONE());
}

void
mrb_mruby_digest_ffi_gem_final(mrb_state* mrb) {
  /* finalizer */
}
