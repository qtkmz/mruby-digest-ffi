#include <mruby.h>
#include <mruby/variable.h>
#include <mruby/class.h>
#include <mruby/data.h>
#include <sys/types.h>
#include <dlfcn.h>
#include <ffi.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/*---------------------------------------------------------------------------*/
#define MD5_LBLOCK 16
#define SHA_LBLOCK 16
#define SHA512_CBLOCK (SHA_LBLOCK*8)

typedef unsigned long MD5_LONG;
typedef unsigned long SHA_LONG;
typedef unsigned long long SHA_LONG64;

typedef struct {
  MD5_LONG A,B,C,D;
  MD5_LONG Nl,Nh;
  MD5_LONG data[MD5_LBLOCK];
  unsigned int num;
} MD5_CTX;

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

typedef struct {
  const char *name;
  size_t digest_size;

  const char *init_func_name;
  const char *update_func_name;
  const char *final_func_name;

  size_t ctx_size;
} mrb_digest_conf;

typedef struct {
  void *ctx;
  size_t ctx_size;
  size_t digest_size;

  void *handle;
  void *func_init;
  void *func_update;
  void *func_final;
} mrb_digest;

#define MRB_DIGEST_AVAILABLE_SIZ    128  // md5=16, sha1=20, sha512=64
#define MRB_HEXDIGEST_AVAILABLE_SIZ 256

static mrb_digest_conf conf[] = {
  { "Digest::MD5", 16, "MD5_Init", "MD5_Update", "MD5_Final", sizeof(MD5_CTX) },
  { "Digest::SHA1", 20, "SHA1_Init", "SHA1_Update", "SHA1_Final", sizeof(SHA_CTX) },
  { "Digest::SHA256", 32, "SHA256_Init", "SHA256_Update", "SHA256_Final", sizeof(SHA256_CTX) },
  { "Digest::SHA384", 48, "SHA384_Init", "SHA384_Update", "SHA384_Final", sizeof(SHA512_CTX) },
  { "Digest::SHA512", 64, "SHA512_Init", "SHA512_Update", "SHA512_Final", sizeof(SHA512_CTX) }
};

static mrb_value mrb_md5_init(mrb_state *mrb, mrb_value self);
static mrb_value mrb_md5_update(mrb_state *mrb, mrb_value self);
static mrb_value mrb_md5_digest(mrb_state *mrb, mrb_value self);
static mrb_value mrb_md5_hexdigest(mrb_state *mrb, mrb_value self);
void mrb_md5_free(mrb_state *mrb, void *p);

static mrb_digest_conf* get_digest_conf(const char *class_name);
static mrb_value init(mrb_state *mrb, mrb_value self);
static mrb_digest* alloc_instance_data(mrb_state *mrb, size_t ctx_size);
static void call_init(mrb_state *mrb, void (*fn)(void), void *ctx);
static void call_update(mrb_state *mrb, void (*fn)(void), void *ctx, unsigned char *s, size_t len);
static void call_final(mrb_state *mrb, void (*fn)(void), void *ctx, unsigned char *md);
static char* digest2hex(char *hex, unsigned char *digest, size_t digest_size);

static mrb_value mrb_sha1_init(mrb_state *mrb, mrb_value self);
static mrb_value mrb_sha256_init(mrb_state *mrb, mrb_value self);
static mrb_value mrb_sha384_init(mrb_state *mrb, mrb_value self);
static mrb_value mrb_sha512_init(mrb_state *mrb, mrb_value self);

static const mrb_data_type mrb_md5_type = {
  "mrb_digest_base_ffi_md5", mrb_md5_free,
};

static mrb_value
mrb_md5_init(mrb_state *mrb, mrb_value self) {
  return init(mrb, self);
}

static mrb_value
mrb_md5_update(mrb_state *mrb, mrb_value self) {
  mrb_digest *digest;
  unsigned char *s;
  mrb_int len;

  mrb_get_args(mrb, "s", &s, &len);

  digest = mrb_get_datatype(mrb, self, &mrb_md5_type);
  if (digest == NULL) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  call_update(mrb, FFI_FN(digest->func_update), digest->ctx, s, len);

  return self;
}

static mrb_value
mrb_md5_digest(mrb_state *mrb, mrb_value self) {
  mrb_digest *digest;
  void *ctx_tmp;
  unsigned char md[MRB_DIGEST_AVAILABLE_SIZ];

  digest = mrb_get_datatype(mrb, self, &mrb_md5_type);
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

static mrb_value
mrb_md5_hexdigest(mrb_state *mrb, mrb_value self) {
  mrb_digest *digest;
  void *ctx_tmp;
  unsigned char md[MRB_DIGEST_AVAILABLE_SIZ];
  char hex[MRB_HEXDIGEST_AVAILABLE_SIZ];

  digest = mrb_get_datatype(mrb, self, &mrb_md5_type);
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

void
mrb_md5_free(mrb_state *mrb, void *p) {
  mrb_digest *digest = (mrb_digest *)p;

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

static mrb_value
init(mrb_state *mrb, mrb_value self) {
  mrb_digest *digest;
  char *err_msg;
  mrb_digest_conf *c;

  c = get_digest_conf(mrb_obj_classname(mrb, self));
  if (c == NULL) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  digest = alloc_instance_data(mrb, c->ctx_size);
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

  DATA_PTR(self) = digest;
  DATA_TYPE(self) = &mrb_md5_type;

  return self;
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

static char*
digest2hex(char *hex, unsigned char *digest, size_t digest_size) {
  int i;
  for (i = 0; i < digest_size; i++) {
    sprintf(hex + (i * 2), "%02x", digest[i]);
  }
  return hex;
}

static mrb_value
mrb_sha1_init(mrb_state *mrb, mrb_value self) {
  return init(mrb, self);
}

static mrb_value
mrb_sha256_init(mrb_state *mrb, mrb_value self) {
  return init(mrb, self);
}

static mrb_value
mrb_sha384_init(mrb_state *mrb, mrb_value self) {
  return init(mrb, self);
}

static mrb_value
mrb_sha512_init(mrb_state *mrb, mrb_value self) {
  return init(mrb, self);
}

void
mrb_mruby_digest_ffi_gem_init(mrb_state* mrb) {
  struct RClass *digest;
  struct RClass *md5;
  struct RClass *sha1;
  struct RClass *sha256;
  struct RClass *sha384;
  struct RClass *sha512;

  digest = mrb_define_module(mrb, "Digest");

  md5 = mrb_define_class_under(mrb, digest, "MD5", mrb->object_class);
  sha1 = mrb_define_class_under(mrb, digest, "SHA1", mrb->object_class);
  sha256 = mrb_define_class_under(mrb, digest, "SHA256", mrb->object_class);
  sha384 = mrb_define_class_under(mrb, digest, "SHA384", mrb->object_class);
  sha512 = mrb_define_class_under(mrb, digest, "SHA512", mrb->object_class);

  MRB_SET_INSTANCE_TT(md5, MRB_TT_DATA);
  mrb_define_method(mrb, md5, "initialize", mrb_md5_init, MRB_ARGS_NONE());
  mrb_define_method(mrb, md5, "update", mrb_md5_update, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, md5, "digest", mrb_md5_digest, MRB_ARGS_NONE());
  mrb_define_method(mrb, md5, "hexdigest", mrb_md5_hexdigest, MRB_ARGS_NONE());

  MRB_SET_INSTANCE_TT(sha1, MRB_TT_DATA);
  mrb_define_method(mrb, sha1, "initialize", mrb_sha1_init, MRB_ARGS_NONE());
  mrb_define_method(mrb, sha1, "update", mrb_md5_update, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, sha1, "digest", mrb_md5_digest, MRB_ARGS_NONE());
  mrb_define_method(mrb, sha1, "hexdigest", mrb_md5_hexdigest, MRB_ARGS_NONE());

  MRB_SET_INSTANCE_TT(sha256, MRB_TT_DATA);
  mrb_define_method(mrb, sha256, "initialize", mrb_sha256_init, MRB_ARGS_NONE());
  mrb_define_method(mrb, sha256, "update", mrb_md5_update, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, sha256, "digest", mrb_md5_digest, MRB_ARGS_NONE());
  mrb_define_method(mrb, sha256, "hexdigest", mrb_md5_hexdigest, MRB_ARGS_NONE());

  MRB_SET_INSTANCE_TT(sha384, MRB_TT_DATA);
  mrb_define_method(mrb, sha384, "initialize", mrb_sha384_init, MRB_ARGS_NONE());
  mrb_define_method(mrb, sha384, "update", mrb_md5_update, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, sha384, "digest", mrb_md5_digest, MRB_ARGS_NONE());
  mrb_define_method(mrb, sha384, "hexdigest", mrb_md5_hexdigest, MRB_ARGS_NONE());

  MRB_SET_INSTANCE_TT(sha512, MRB_TT_DATA);
  mrb_define_method(mrb, sha512, "initialize", mrb_sha512_init, MRB_ARGS_NONE());
  mrb_define_method(mrb, sha512, "update", mrb_md5_update, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, sha512, "digest", mrb_md5_digest, MRB_ARGS_NONE());
  mrb_define_method(mrb, sha512, "hexdigest", mrb_md5_hexdigest, MRB_ARGS_NONE());
}

void
mrb_mruby_digest_ffi_gem_final(mrb_state* mrb) {
  /* finalizer */
}
