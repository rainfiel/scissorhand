
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <dlfcn.h>
#include <openssl/evp.h>
// #include <sqlite3.h>

#include "elf_hooker.h"
#include "inlinehook.h"

static void* (*__old_impl_dlopen)(const char* filename, int flag);

static int (*__old_impl_connect)(int sockfd,struct sockaddr * serv_addr,int addrlen);

static void* (*__old_impl_android_dlopen_ext)(const char* filename, int flags, const void* extinfo);

static int (*__old_impl_evp_cipherinit)(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                   const unsigned char *key, const unsigned char *iv,
                   int enc);

static int (*__old_impl_evp_cipherinit_ex)(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                      ENGINE *impl, const unsigned char *key,
                      const unsigned char *iv, int enc);

static int (*__old_impl_fopen)(const char *pathname, int flags);

static int (*__old_impl_sqlite_open)(const char* name, void **ppDb);

static EVP_CIPHER* (*__old_impl_EVP_get_cipherbyname)(const char *name);

static int (*__old_impl_EVP_CipherUpdate)(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
                     const unsigned char *in, int inl);

static int (*__old_impl_PKCS5_PBKDF2_HMAC_SHA1)(const char *pass, int passlen,
                           const unsigned char *salt, int saltlen, int iter,
                           int keylen, unsigned char *out);

static size_t (*__old_impl_strlen)(const char *str);

static void * (*__old_imp_memcpy)(void *str1, const void *str2, size_t n);

static void * (*__old_impl__ZN5YiDou15YDSqliteManager6createESsSs)(std::string a, std::string b);

static int (*__old_impl__ZN5YiDou15YDSqliteManagerinit)(std::string a, std::string b);

static void (*__old_impl__ZN7cocos2d5CCLogEPKcz)(const char* fmt, ...);

static int (*__old_imp_EVP_DecryptInit)(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
         unsigned char *key, unsigned char *iv);

extern "C" {

    static void* __nativehook_impl_dlopen(const char* filename, int flag)
    {
        log_info("__nativehook_impl_dlopen -> (%s)\n", filename);
        void* res = __old_impl_dlopen(filename, flag);
        return res;
    }

    static int __nativehook_impl_connect(int sockfd,struct sockaddr * serv_addr,int addrlen)
    {
        log_info("__nativehook_impl_connect ->\n");
        int res = __old_impl_connect(sockfd, serv_addr, addrlen);
        return res;
    }

    static void* __nativehook_impl_android_dlopen_ext(const char* filename, int flags, const void* extinfo)
    {
        log_info("__nativehook_impl_android_dlopen_ext -> (%s)\n", filename);
        void* res = __old_impl_android_dlopen_ext(filename, flags, extinfo);
        return res;
    }

// int EVP_CipherInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
//                    const unsigned char *key, const unsigned char *iv,
//                    int enc);
    static int __nativehook_impl_evp_cipherinit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                   const unsigned char *key, const unsigned char *iv,
                   int enc)
    {
        log_info("__nativehook_impl_evp_cipherinit -> (%s)\n", key);
        return __old_impl_evp_cipherinit(ctx, cipher, key, iv, enc);
    }

// int EVP_CipherInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
//                       ENGINE *impl, const unsigned char *key,
//                       const unsigned char *iv, int enc);
    static int __nativehook_impl_evp_cipherinit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                      ENGINE *impl, const unsigned char *key,
                      const unsigned char *iv, int enc)
    {
        int sz = strlen((char*)key);
        char* buf = (char*)malloc(2*sz+1);
        char* pt = buf;
        for (int i=0; i < sz; i++) {
            pt += sprintf(pt, "%02X", key[i]);
        }
        log_info("__nativehook_impl_evp_cipherinit_ex -> %d (%s)\n", sz, buf);
        free(buf);
        return __old_impl_evp_cipherinit_ex(ctx, cipher, impl, key, iv, enc);
    }

    static int __nativehook_impl_fopen(const char *pathname, int flags)
    {
        log_info("__nativehook_impl_fopen -> (%s)\n", pathname);
        return __old_impl_fopen(pathname, flags);
    }

    static int __nativehook_impl_sqlite_open(const char* name, void **ppDb)
    {
        log_info("__nativehook_impl_sqlite_open -> (%s)\n", name);
        return __old_impl_sqlite_open(name, ppDb);
    }

    static EVP_CIPHER* __nativehook_impl_evp_get_cipherbyname(const char* name)
    {
        log_info("__nativehook_impl_evp_get_cipherbyname -> (%s)\n", name);
        return __old_impl_EVP_get_cipherbyname(name);
    }

    static int __nativehook_impl_evp_cipherupdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
                     const unsigned char *in, int inl)
    {
        log_info("__nativehook_impl_evp_cipherupdate -> \n");
        return  __old_impl_EVP_CipherUpdate(ctx, out, outl, in, inl);
    }

    static int __nativehook_impl_PKCS5_PBKDF2_HMAC_SHA1(const char *pass, int passlen,
                           const unsigned char *salt, int saltlen, int iter,
                           int keylen, unsigned char *out)
    {
        log_info("__nativehook_impl_PKCS5_PBKDF2_HMAC_SHA1 -> (%s)\n", pass);
        return __old_impl_PKCS5_PBKDF2_HMAC_SHA1(pass, passlen, salt, saltlen, iter, keylen, out);
    }

    static size_t __nativehook_impl_strlen(const char *str)
    {
        log_info("__nativehook_impl_strlen -> (%s)\n", str);
        return __old_impl_strlen(str);
    }

    static void * __nativehook_impl_memcpy(void *str1, const void *str2, size_t n)
    {
        log_info("__nativehook_impl_memcpy -> (%s)\n", str2);        
        return __old_imp_memcpy(str1, str2, n);
    }

    static void *__nativehook_impl__ZN5YiDou15YDSqliteManager6createESsSs(std::string a, std::string b)
    {
        log_info("__nativehook_impl__ZN5YiDou15YDSqliteManager6createESsSs -> (%s, %s)\n", a.c_str(), b.c_str());    
        return __old_impl__ZN5YiDou15YDSqliteManager6createESsSs(a, b);
    }


    static int __nativehook_impl__ZN5YiDou15YDSqliteManagerinit(std::string a, std::string b)
    {
        log_info("__nativehook_impl__ZN5YiDou15YDSqliteManagerinit -> (%s, %s)\n", a.c_str(), b.c_str());    
        return __old_impl__ZN5YiDou15YDSqliteManagerinit(a, b);
    }


    static void __nativehook_impl__ZN7cocos2d5CCLogEPKcz(const char* fmt, ...)
    {
        va_list ap;
        va_start(ap, fmt);
        log_info(fmt, ap);
        va_end(ap);
    }


    static int __nativehook_imp_EVP_DecryptInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
         unsigned char *key, unsigned char *iv)
    {
        log_info("__nativehook_imp_EVP_DecryptInit -> (%s, %s)\n", key, iv);    
        return __old_imp_EVP_DecryptInit(ctx, type, key, iv);
    }

}

static bool __prehook(const char* module_name, const char* func_name)
{
    if (strstr(module_name, "libgame.so") != NULL)
    {
       return true;
    }
    return false;
}

#if (ELFHOOK_STANDALONE)

int main(int argc, char* argv[])
{
    char ch = 0;
    elf_hooker hooker;

    void* h = dlopen("libart.so", RTLD_LAZY);
    void* f = dlsym(h,"artAllocObjectFromCodeResolvedRegion");
    log_info("artAllocObjectFromCodeResolvedRegion : %p\n", f);

    hooker.set_prehook_cb(__prehook);
    hooker.phrase_proc_maps();
    hooker.dump_module_list();
    hooker.hook_all_modules("dlopen", (void*)__nativehook_impl_dlopen, (void**)&__old_impl_dlopen);
    hooker.hook_all_modules("connect", (void*)__nativehook_impl_connect, (void**)&__old_impl_connect);

    do {
        ch = getc(stdin);
    } while(ch != 'q');
    return 0;
}

#else

#include <jni.h>

static char* __class_name = "com/wadahana/testhook/ElfHooker";
static elf_hooker __hooker;
static JavaVM* __java_vm = NULL;
static bool __is_attached = false;

static JNIEnv* __getEnv(bool* attached);
static void __releaseEnv(bool attached);
static int __set_hook(JNIEnv *env, jobject thiz);
static int __test(JNIEnv *env, jobject thiz);
static int __elfhooker_init(JavaVM* vm, JNIEnv* env);
static void __elfhooker_deinit(void);

static JNINativeMethod __methods[] =
{
    {"setHook","()I",(void *)__set_hook },
    {"test","()I",(void *)__test },
};

static int __set_hook(JNIEnv *env, jobject thiz)
{
    log_info("__set_hook() -->\r\n");
//    __hooker.set_prehook_cb(__prehook);
    __hooker.phrase_proc_maps();
    __hooker.dump_module_list();
    __hooker.dump_proc_maps();
    // __hooker.hook_all_modules("dlopen", (void*)__nativehook_impl_dlopen, (void**)&__old_impl_dlopen);
    // __hooker.hook_all_modules("connect", (void*)__nativehook_impl_connect, (void**)&__old_impl_connect);
    // __hooker.hook_all_modules("android_dlopen_ext", (void*)__nativehook_impl_android_dlopen_ext, (void**)&__old_impl_android_dlopen_ext);

    __hooker.hook_all_modules("EVP_CipherInit", (void*)__nativehook_impl_evp_cipherinit, (void**)&__old_impl_evp_cipherinit);

#if 0
    void* h = dlopen("libart.so", RTLD_LAZY);
    if (h != NULL) {
        void* f = dlsym(h,"artAllocObjectFromCodeResolvedRegion");
        log_info("artAllocObjectFromCodeResolvedRegion : %p\n", f);
    } else {
        log_error("open libart.so fail\n");
    }
#endif
    return 0;
}

static int __test(JNIEnv *env, jobject thiz)
{
    log_info("__test() -->\r\n");
//    __hooker.dump_proc_maps();
    return 0;
}

static int __elfhooker_register_native_methods(JNIEnv* env, const char* class_name,
                                JNINativeMethod* methods, int num_methods)
{

    log_info("RegisterNatives start for \'%s\'", __class_name);

    jclass clazz = env->FindClass(class_name);
    if (clazz == NULL)
    {
        log_error("Native registration unable to find class \'%s\'", class_name);
        return JNI_FALSE;
    }

    if (env->RegisterNatives(clazz, methods, num_methods) < 0)
    {
        log_error("RegisterNatives failed for \'%s\'", class_name );
        return JNI_FALSE;
    }

    return JNI_TRUE;
}

static int __elfhooker_init(JavaVM* vm, JNIEnv* env)
{
    log_info("hookwrapper_init() -->\r\n");
    if (!__elfhooker_register_native_methods(env, __class_name,
                __methods, sizeof(__methods) / sizeof(__methods[0])))
    {
        log_error("register hookJNIMethod fail, \r\n");
        __elfhooker_deinit();
        return -2;
    }

  return 0;
}

static void __elfhooker_deinit(void)
{
    log_info("hookwrapper_deinit()->\r\n");
    return;
}


JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved)
{
    JNIEnv* env = NULL;
    bool attached;
    __java_vm = vm;

    if ((env = __getEnv(&__is_attached)) == NULL)
    {
        log_error("getEnv fail\r\n");
        return -1;
    }
    assert(!__is_attached);
    if (__elfhooker_init(vm, env) < 0)
    {
        log_error("__elfhooker_init fail\r\n");
        return -1;
    }
    return JNI_VERSION_1_4;
}

JNIEXPORT void JNICALL JNI_OnUnload(JavaVM* vm, void* reserved)
{
    bool attached;
    JNIEnv* env = __getEnv(&__is_attached);
    assert(!__is_attached);

    __elfhooker_deinit();
    return ;
}

static JNIEnv* __getEnv(bool* attached)
{
    JNIEnv* env = NULL;
    *attached = false;
    int ret = __java_vm->GetEnv((void**)&env, JNI_VERSION_1_4);
    if (ret == JNI_EDETACHED)
    {
        if (0 != __java_vm->AttachCurrentThread(&env, NULL)) {
            return NULL;
        }
        *attached = true;
        return env;
    }

    if (ret != JNI_OK) {
        return NULL;
    }

    return env;
}

static void __releaseEnv(bool attached)
{
    if (attached)
        __java_vm->DetachCurrentThread();
}

void __attribute__ ((constructor)) libElfHook_main()
{
    log_info(".............................loaded\r\n");

    elf_hooker hooker;

    // void* h = dlopen("libart.so", RTLD_LAZY);
    // void* f = dlsym(h,"artAllocObjectFromCodeResolvedRegion");
    // log_info("artAllocObjectFromCodeResolvedRegion : %p\n", f);

    hooker.set_prehook_cb(__prehook);
    hooker.phrase_proc_maps();
    // hooker.dump_module_list();
    hooker.hook_all_modules("EVP_CipherInit", (void*)__nativehook_impl_evp_cipherinit, (void**)&__old_impl_evp_cipherinit);
    hooker.hook_all_modules("EVP_CipherInit_ex", (void*)__nativehook_impl_evp_cipherinit_ex, (void**)&__old_impl_evp_cipherinit_ex);
 
    // hooker.hook_all_modules("strlen", (void*)__nativehook_impl_strlen, (void**)&__old_impl_strlen);
    // hooker.hook_all_modules("EVP_get_cipherbyname", (void*)__nativehook_impl_evp_get_cipherbyname, (void**)&__old_impl_EVP_get_cipherbyname);
    hooker.hook_all_modules("EVP_CipherUpdate", (void*)__nativehook_impl_evp_cipherupdate, (void**)&__old_impl_EVP_CipherUpdate);
    hooker.hook_all_modules("EVP_DecryptInit", (void*)__nativehook_imp_EVP_DecryptInit, (void**)&__old_imp_EVP_DecryptInit);
    hooker.hook_all_modules("PKCS5_PBKDF2_HMAC_SHA1", (void*)__nativehook_impl_PKCS5_PBKDF2_HMAC_SHA1, (void**)&__old_impl_PKCS5_PBKDF2_HMAC_SHA1);
    // hooker.set_prehook_cb(__prehook);
    // hooker.hook_all_modules("memcpy", (void*)__nativehook_impl_memcpy, (void**)&__old_imp_memcpy);
    // hooker.hook_all_modules("fopen", (void*)__nativehook_impl_fopen, (void**)&__old_impl_fopen);
    hooker.hook_all_modules("sqlite3_open", (void*)__nativehook_impl_sqlite_open, (void**)&__old_impl_sqlite_open);
    // hooker.hook_all_modules("_ZN5YiDou15YDSqliteManager6createESsSs", (void*)__nativehook_impl__ZN5YiDou15YDSqliteManager6createESsSs, (void**)&__old_impl__ZN5YiDou15YDSqliteManager6createESsSs);
    // hooker.hook_all_modules("_ZN5YiDou15YDSqliteManager4initESsSs", (void*)__nativehook_impl__ZN5YiDou15YDSqliteManagerinit, (void**)&__old_impl__ZN5YiDou15YDSqliteManagerinit);
    // hooker.hook_all_modules("EVP_sha1", (void*)__nativehook_impl__ZN5YiDou15YDSqliteManager6createESsSs, (void**)&__old_impl__ZN5YiDou15YDSqliteManager6createESsSs);
    hooker.hook_all_modules("_ZN7cocos2d5CCLogEPKcz", (void*)__nativehook_impl__ZN7cocos2d5CCLogEPKcz, (void**)&__old_impl__ZN7cocos2d5CCLogEPKcz);
    // hooker.dump_symbols();
    // hooker.dump_dynamics();
    // hooker.dump_segments();
    // hooker.dump_sections();
    // hooker.dump_proc_maps();
}
#endif
