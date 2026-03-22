#include <jni.h>
#include <jvmti.h>
#include <android/log.h>
#include <android/dlext.h>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <dlfcn.h>
#include <sys/stat.h>
#include <sys/system_properties.h>
#include <errno.h>
#include <elf.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

#include <time.h>
#include <pthread.h>
#include "debugger.h"
#include "protocol.h"

#define LOG_TAG "ArtJitTracer"
#define ALOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define ALOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)
#define ALOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// ---------------------------------------------------------------------------
// Globals
// ---------------------------------------------------------------------------
static bool g_have_bytecodes = false;
static bool g_have_local_vars = false;
static const char* kDumpDir = "/data/local/tmp/jit_dump";

// Dump DEX bytecodes of a method to a file.
// File: /data/local/tmp/jit_dump/<class>.<method>.dex
static void DumpBytecodes(jvmtiEnv* jvmti, jmethodID method,
                           const char* class_sig, const char* method_name) {
    if (!g_have_bytecodes) return;

    jint bytecode_count = 0;
    unsigned char* bytecodes = nullptr;

    jvmtiError err = jvmti->GetBytecodes(method, &bytecode_count, &bytecodes);
    if (err != JVMTI_ERROR_NONE || bytecodes == nullptr || bytecode_count == 0) {
        if (err != JVMTI_ERROR_NONE) {
            ALOGW("[BYTECODE] GetBytecodes failed: %d for %s.%s",
                  err, class_sig, method_name);
        }
        return;
    }

    // Build filename: replace / with . in class sig, strip L and ;
    char filename[512];
    char clean_class[256];
    size_t j = 0;
    for (size_t i = 0; class_sig[i] && j < sizeof(clean_class) - 1; i++) {
        char c = class_sig[i];
        if (c == 'L') continue;           // skip leading L
        if (c == ';') continue;           // skip trailing ;
        if (c == '/') c = '.';            // Lcom/foo/ -> com.foo
        clean_class[j++] = c;
    }
    clean_class[j] = '\0';

    snprintf(filename, sizeof(filename), "%s/%s.%s.dex",
             kDumpDir, clean_class, method_name);

    FILE* f = fopen(filename, "wb");
    if (!f) {
        ALOGW("[BYTECODE] Failed to open %s: %s", filename, strerror(errno));
        jvmti->Deallocate(bytecodes);
        return;
    }

    fwrite(bytecodes, 1, bytecode_count, f);
    fclose(f);

    ALOGI("[BYTECODE] %s.%s → %d bytes → %s",
          class_sig, method_name, bytecode_count, filename);

    jvmti->Deallocate(bytecodes);
}

// ---------------------------------------------------------------------------
// Crypto key extraction via JNI
// When JVMTI catches crypto method calls, use local variable access + JNI
// to extract algorithm names, raw key bytes, IVs, and plaintext/ciphertext.
// Requires: can_access_local_variables capability
// ---------------------------------------------------------------------------

// Clear any pending JNI exception; returns true if one was pending
static bool ClearJniException(JNIEnv* jni) {
    if (jni->ExceptionCheck()) {
        jni->ExceptionClear();
        return true;
    }
    return false;
}

// Compute the slot number for parameter N in ART/Dalvik.
// Unlike the JVM (slot 0 = this), Dalvik puts params in the LAST registers:
//   [local0 | local1 | ... | this | arg0 | arg1 | ...]
// So: first_param_slot = max_locals - args_size
// param_idx: 0 = this (instance), 1 = first arg, 2 = second arg, etc.
// Returns -1 on failure.
static jint GetParamSlot(jvmtiEnv* jvmti, jmethodID method, int param_idx) {
    jint max_locals = 0;
    jint args_size = 0;
    if (jvmti->GetMaxLocals(method, &max_locals) != JVMTI_ERROR_NONE) return -1;
    if (jvmti->GetArgumentsSize(method, &args_size) != JVMTI_ERROR_NONE) return -1;
    jint slot = (max_locals - args_size) + param_idx;
    if (slot < 0 || slot >= max_locals) return -1;
    return slot;
}

// Log a Java byte[] as hex (first max_bytes bytes)
static void LogByteArrayHex(JNIEnv* jni, jbyteArray arr,
                             const char* label, int max_bytes = 64) {
    if (!arr) {
        ALOGI("[CRYPTO]   %s: (null)", label);
        return;
    }
    jint len = jni->GetArrayLength(arr);
    int dump_len = (len < max_bytes) ? len : max_bytes;

    jbyte* bytes = jni->GetByteArrayElements(arr, nullptr);
    if (!bytes) {
        ALOGI("[CRYPTO]   %s: (%d bytes, unreadable)", label, len);
        return;
    }

    // 2 hex chars per byte + null terminator
    char hex[512];
    int pos = 0;
    for (int i = 0; i < dump_len && pos < (int)sizeof(hex) - 16; i++) {
        pos += snprintf(hex + pos, sizeof(hex) - pos, "%02x",
                        (unsigned char)bytes[i]);
    }
    jni->ReleaseByteArrayElements(arr, bytes, JNI_ABORT);

    if (dump_len < len) {
        ALOGI("[CRYPTO]   %s: %s... (%d bytes total)", label, hex, len);
    } else {
        ALOGI("[CRYPTO]   %s: %s (%d bytes)", label, hex, len);
    }
}

// Extract info when Cipher.init(int opmode, Key key, ...) is called
// Param 0 = this (Cipher), param 1 = opmode (int), param 2 = key (Key)
static void InspectCipherInit(jvmtiEnv* jvmti, JNIEnv* jni, jthread thread,
                               jmethodID method) {
    jint p0 = GetParamSlot(jvmti, method, 0);  // this
    jint p1 = GetParamSlot(jvmti, method, 1);  // opmode
    jint p2 = GetParamSlot(jvmti, method, 2);  // key
    if (p0 < 0) return;

    jobject cipher_obj = nullptr;
    jvmtiError err = jvmti->GetLocalObject(thread, 0, p0, &cipher_obj);
    if (err != JVMTI_ERROR_NONE || !cipher_obj) return;

    jclass cipher_class = jni->GetObjectClass(cipher_obj);

    // Algorithm name
    jmethodID getAlgo = jni->GetMethodID(cipher_class, "getAlgorithm",
                                          "()Ljava/lang/String;");
    if (!ClearJniException(jni) && getAlgo) {
        jstring algo = (jstring)jni->CallObjectMethod(cipher_obj, getAlgo);
        if (!ClearJniException(jni) && algo) {
            const char* s = jni->GetStringUTFChars(algo, nullptr);
            ALOGI("[CRYPTO] Cipher.init: algorithm=%s", s);
            jni->ReleaseStringUTFChars(algo, s);
            jni->DeleteLocalRef(algo);
        }
    }

    // Opmode: 1=ENCRYPT, 2=DECRYPT, 3=WRAP, 4=UNWRAP
    if (p1 >= 0) {
        jint opmode = 0;
        err = jvmti->GetLocalInt(thread, 0, p1, &opmode);
        if (err == JVMTI_ERROR_NONE) {
            const char* mode_str = (opmode == 1) ? "ENCRYPT" :
                                   (opmode == 2) ? "DECRYPT" :
                                   (opmode == 3) ? "WRAP" :
                                   (opmode == 4) ? "UNWRAP" : "UNKNOWN";
            ALOGI("[CRYPTO]   mode=%s (%d)", mode_str, opmode);
        }
    }

    // Key argument — call Key.getEncoded() for raw bytes
    if (p2 >= 0) {
        jobject key_obj = nullptr;
        err = jvmti->GetLocalObject(thread, 0, p2, &key_obj);
        if (err == JVMTI_ERROR_NONE && key_obj) {
            jclass key_class = jni->GetObjectClass(key_obj);

            jmethodID getEncoded = jni->GetMethodID(key_class, "getEncoded", "()[B");
            if (!ClearJniException(jni) && getEncoded) {
                jbyteArray key_bytes = (jbyteArray)jni->CallObjectMethod(key_obj, getEncoded);
                if (!ClearJniException(jni) && key_bytes) {
                    LogByteArrayHex(jni, key_bytes, "KEY");
                    jni->DeleteLocalRef(key_bytes);
                }
            }

            jmethodID getKeyAlgo = jni->GetMethodID(key_class, "getAlgorithm",
                                                      "()Ljava/lang/String;");
            if (!ClearJniException(jni) && getKeyAlgo) {
                jstring ka = (jstring)jni->CallObjectMethod(key_obj, getKeyAlgo);
                if (!ClearJniException(jni) && ka) {
                    const char* s = jni->GetStringUTFChars(ka, nullptr);
                    ALOGI("[CRYPTO]   key_algorithm=%s", s);
                    jni->ReleaseStringUTFChars(ka, s);
                    jni->DeleteLocalRef(ka);
                }
            }
            jni->DeleteLocalRef(key_class);
            jni->DeleteLocalRef(key_obj);
        }
    }

    jni->DeleteLocalRef(cipher_class);
    jni->DeleteLocalRef(cipher_obj);
}

// Extract info when Cipher.doFinal(...) is called
// Cipher is already initialized — read algorithm + IV from this
// Param 0 = this (Cipher), param 1 = input byte[] (if present)
static void InspectCipherDoFinal(jvmtiEnv* jvmti, JNIEnv* jni, jthread thread,
                                  jmethodID method) {
    jint p0 = GetParamSlot(jvmti, method, 0);
    jint p1 = GetParamSlot(jvmti, method, 1);
    if (p0 < 0) return;

    jobject cipher_obj = nullptr;
    jvmtiError err = jvmti->GetLocalObject(thread, 0, p0, &cipher_obj);
    if (err != JVMTI_ERROR_NONE || !cipher_obj) return;

    jclass cipher_class = jni->GetObjectClass(cipher_obj);

    // Algorithm
    jmethodID getAlgo = jni->GetMethodID(cipher_class, "getAlgorithm",
                                          "()Ljava/lang/String;");
    if (!ClearJniException(jni) && getAlgo) {
        jstring algo = (jstring)jni->CallObjectMethod(cipher_obj, getAlgo);
        if (!ClearJniException(jni) && algo) {
            const char* s = jni->GetStringUTFChars(algo, nullptr);
            ALOGI("[CRYPTO] Cipher.doFinal: algorithm=%s", s);
            jni->ReleaseStringUTFChars(algo, s);
            jni->DeleteLocalRef(algo);
        }
    }

    // IV (set by prior Cipher.init call)
    jmethodID getIV = jni->GetMethodID(cipher_class, "getIV", "()[B");
    if (!ClearJniException(jni) && getIV) {
        jbyteArray iv = (jbyteArray)jni->CallObjectMethod(cipher_obj, getIV);
        if (!ClearJniException(jni) && iv) {
            LogByteArrayHex(jni, iv, "IV");
            jni->DeleteLocalRef(iv);
        }
    }

    // Input byte[] (for doFinal(byte[]) overloads)
    if (p1 >= 0) {
        jobject input_obj = nullptr;
        err = jvmti->GetLocalObject(thread, 0, p1, &input_obj);
        if (err == JVMTI_ERROR_NONE && input_obj) {
            jclass byte_arr_class = jni->FindClass("[B");
            if (byte_arr_class && jni->IsInstanceOf(input_obj, byte_arr_class)) {
                LogByteArrayHex(jni, (jbyteArray)input_obj, "INPUT", 128);
            }
            if (byte_arr_class) jni->DeleteLocalRef(byte_arr_class);
            jni->DeleteLocalRef(input_obj);
        }
    }

    jni->DeleteLocalRef(cipher_class);
    jni->DeleteLocalRef(cipher_obj);
}

// Extract raw key bytes from SecretKeySpec(byte[] key, String algorithm)
// At <init> entry, this is uninitialized — read args, not this
// Param 1 = key byte[], param 2 = algorithm String (for 2-arg ctor)
static void InspectSecretKeySpecInit(jvmtiEnv* jvmti, JNIEnv* jni, jthread thread,
                                      jmethodID method) {
    jint p1 = GetParamSlot(jvmti, method, 1);  // key byte[]
    jint p2 = GetParamSlot(jvmti, method, 2);  // algorithm String

    ALOGI("[CRYPTO] SecretKeySpec.<init>:");

    // Key bytes
    if (p1 >= 0) {
        jobject key_obj = nullptr;
        jvmtiError err = jvmti->GetLocalObject(thread, 0, p1, &key_obj);
        if (err == JVMTI_ERROR_NONE && key_obj) {
            jclass byte_arr_class = jni->FindClass("[B");
            if (byte_arr_class && jni->IsInstanceOf(key_obj, byte_arr_class)) {
                LogByteArrayHex(jni, (jbyteArray)key_obj, "KEY");
            }
            if (byte_arr_class) jni->DeleteLocalRef(byte_arr_class);
            jni->DeleteLocalRef(key_obj);
        }
    }

    // Algorithm string
    if (p2 >= 0) {
        jobject algo_obj = nullptr;
        jvmtiError err = jvmti->GetLocalObject(thread, 0, p2, &algo_obj);
        if (err == JVMTI_ERROR_NONE && algo_obj) {
            jclass str_class = jni->FindClass("java/lang/String");
            if (str_class && jni->IsInstanceOf(algo_obj, str_class)) {
                const char* s = jni->GetStringUTFChars((jstring)algo_obj, nullptr);
                if (s) {
                    ALOGI("[CRYPTO]   algorithm=%s", s);
                    jni->ReleaseStringUTFChars((jstring)algo_obj, s);
                }
            }
            if (str_class) jni->DeleteLocalRef(str_class);
            jni->DeleteLocalRef(algo_obj);
        }
    }
}

// Extract IV bytes from IvParameterSpec(byte[] iv)
// Param 1 = iv byte[]
static void InspectIvParameterSpecInit(jvmtiEnv* jvmti, JNIEnv* jni, jthread thread,
                                        jmethodID method) {
    jint p1 = GetParamSlot(jvmti, method, 1);
    ALOGI("[CRYPTO] IvParameterSpec.<init>:");
    if (p1 < 0) return;

    jobject iv_obj = nullptr;
    jvmtiError err = jvmti->GetLocalObject(thread, 0, p1, &iv_obj);
    if (err == JVMTI_ERROR_NONE && iv_obj) {
        jclass byte_arr_class = jni->FindClass("[B");
        if (byte_arr_class && jni->IsInstanceOf(iv_obj, byte_arr_class)) {
            LogByteArrayHex(jni, (jbyteArray)iv_obj, "IV");
        }
        if (byte_arr_class) jni->DeleteLocalRef(byte_arr_class);
        jni->DeleteLocalRef(iv_obj);
    }
}

// Extract HMAC key from Mac.init(Key key)
// Param 0 = this (Mac), param 1 = key (Key)
static void InspectMacInit(jvmtiEnv* jvmti, JNIEnv* jni, jthread thread,
                            jmethodID method) {
    jint p0 = GetParamSlot(jvmti, method, 0);
    jint p1 = GetParamSlot(jvmti, method, 1);
    if (p0 < 0) return;

    jobject mac_obj = nullptr;
    jvmtiError err = jvmti->GetLocalObject(thread, 0, p0, &mac_obj);
    if (err != JVMTI_ERROR_NONE || !mac_obj) return;

    jclass mac_class = jni->GetObjectClass(mac_obj);
    jmethodID getAlgo = jni->GetMethodID(mac_class, "getAlgorithm",
                                          "()Ljava/lang/String;");
    if (!ClearJniException(jni) && getAlgo) {
        jstring algo = (jstring)jni->CallObjectMethod(mac_obj, getAlgo);
        if (!ClearJniException(jni) && algo) {
            const char* s = jni->GetStringUTFChars(algo, nullptr);
            ALOGI("[CRYPTO] Mac.init: algorithm=%s", s);
            jni->ReleaseStringUTFChars(algo, s);
            jni->DeleteLocalRef(algo);
        }
    }

    // Key
    if (p1 >= 0) {
        jobject key_obj = nullptr;
        err = jvmti->GetLocalObject(thread, 0, p1, &key_obj);
        if (err == JVMTI_ERROR_NONE && key_obj) {
            jclass key_class = jni->GetObjectClass(key_obj);
            jmethodID getEncoded = jni->GetMethodID(key_class, "getEncoded", "()[B");
            if (!ClearJniException(jni) && getEncoded) {
                jbyteArray key_bytes = (jbyteArray)jni->CallObjectMethod(key_obj, getEncoded);
                if (!ClearJniException(jni) && key_bytes) {
                    LogByteArrayHex(jni, key_bytes, "HMAC_KEY");
                    jni->DeleteLocalRef(key_bytes);
                }
            }
            jni->DeleteLocalRef(key_class);
            jni->DeleteLocalRef(key_obj);
        }
    }

    jni->DeleteLocalRef(mac_class);
    jni->DeleteLocalRef(mac_obj);
}

// Extract hash input from MessageDigest.update(byte[])
// Param 0 = this (MessageDigest), param 1 = input byte[]
static void InspectMessageDigestUpdate(jvmtiEnv* jvmti, JNIEnv* jni, jthread thread,
                                        jmethodID method) {
    jint p0 = GetParamSlot(jvmti, method, 0);
    jint p1 = GetParamSlot(jvmti, method, 1);
    if (p0 < 0) return;

    jobject md_obj = nullptr;
    jvmtiError err = jvmti->GetLocalObject(thread, 0, p0, &md_obj);
    if (err != JVMTI_ERROR_NONE || !md_obj) return;

    jclass md_class = jni->GetObjectClass(md_obj);
    jmethodID getAlgo = jni->GetMethodID(md_class, "getAlgorithm",
                                          "()Ljava/lang/String;");
    if (!ClearJniException(jni) && getAlgo) {
        jstring algo = (jstring)jni->CallObjectMethod(md_obj, getAlgo);
        if (!ClearJniException(jni) && algo) {
            const char* s = jni->GetStringUTFChars(algo, nullptr);
            ALOGI("[CRYPTO] MessageDigest.update: algorithm=%s", s);
            jni->ReleaseStringUTFChars(algo, s);
            jni->DeleteLocalRef(algo);
        }
    }

    // Input data
    if (p1 >= 0) {
        jobject input_obj = nullptr;
        err = jvmti->GetLocalObject(thread, 0, p1, &input_obj);
        if (err == JVMTI_ERROR_NONE && input_obj) {
            jclass byte_arr_class = jni->FindClass("[B");
            if (byte_arr_class && jni->IsInstanceOf(input_obj, byte_arr_class)) {
                LogByteArrayHex(jni, (jbyteArray)input_obj, "HASH_INPUT", 128);
            }
            if (byte_arr_class) jni->DeleteLocalRef(byte_arr_class);
            jni->DeleteLocalRef(input_obj);
        }
    }

    jni->DeleteLocalRef(md_class);
    jni->DeleteLocalRef(md_obj);
}

// Dispatch crypto inspection based on class + method name
static void InspectCryptoCall(jvmtiEnv* jvmti, JNIEnv* jni, jthread thread,
                               jmethodID method,
                               const char* class_sig, const char* method_name) {
    if (!g_have_local_vars) return;

    if (strcmp(class_sig, "Ljavax/crypto/Cipher;") == 0) {
        if (strcmp(method_name, "init") == 0)
            InspectCipherInit(jvmti, jni, thread, method);
        else if (strcmp(method_name, "doFinal") == 0)
            InspectCipherDoFinal(jvmti, jni, thread, method);
    }
    else if (strcmp(class_sig, "Ljavax/crypto/spec/SecretKeySpec;") == 0 &&
             strcmp(method_name, "<init>") == 0) {
        InspectSecretKeySpecInit(jvmti, jni, thread, method);
    }
    else if (strcmp(class_sig, "Ljavax/crypto/spec/IvParameterSpec;") == 0 &&
             strcmp(method_name, "<init>") == 0) {
        InspectIvParameterSpecInit(jvmti, jni, thread, method);
    }
    else if (strcmp(class_sig, "Ljavax/crypto/Mac;") == 0 &&
             strcmp(method_name, "init") == 0) {
        InspectMacInit(jvmti, jni, thread, method);
    }
    else if (strcmp(class_sig, "Ljava/security/MessageDigest;") == 0 &&
             strcmp(method_name, "update") == 0) {
        InspectMessageDigestUpdate(jvmti, jni, thread, method);
    }
}

// ---------------------------------------------------------------------------
// Security-relevant class prefixes to trace.
// Only method calls matching these prefixes are logged.
// Uses JNI class signature format: "Ljavax/crypto/" matches javax.crypto.*
// ---------------------------------------------------------------------------
static const char* kTracePrefixes[] = {
    // Cryptography
    "Ljavax/crypto/",                   // Cipher, KeyGenerator, Mac, etc.
    "Ljava/security/",                  // MessageDigest, Signature, KeyStore
    "Ljavax/net/ssl/",                  // SSLSocket, SSLContext, TrustManager

    // Reflection (used by packers, obfuscators, malware)
    "Ljava/lang/reflect/",             // Method.invoke, Field.get, Constructor
    "Ljava/lang/Class;.forName",       // Dynamic class loading
    "Ljava/lang/Class;.getMethod",
    "Ljava/lang/Class;.getDeclaredMethod",
    "Ljava/lang/Class;.newInstance",
    "Ljava/lang/ClassLoader;.loadClass",

    // Dynamic code loading (DEX loading, code injection)
    "Ldalvik/system/DexClassLoader",
    "Ldalvik/system/InMemoryDexClassLoader",
    "Ldalvik/system/PathClassLoader",
    "Ldalvik/system/DexFile",
    "Ldalvik/system/BaseDexClassLoader",

    // Network (C2, data exfiltration)
    "Ljava/net/URL;.openConnection",
    "Ljava/net/HttpURLConnection",
    "Lokhttp3/",                        // OkHttp
    "Lcom/android/volley/",             // Volley

    // Process/Runtime execution (shell commands, root exploits)
    "Ljava/lang/Runtime;.exec",
    "Ljava/lang/ProcessBuilder",

    // Content providers / cross-app data access
    "Landroid/content/ContentResolver;.query",
    "Landroid/content/ContentResolver;.insert",
    "Landroid/content/ContentResolver;.delete",

    // Native code loading
    "Ljava/lang/System;.loadLibrary",
    "Ljava/lang/System;.load(",
    "Ljava/lang/Runtime;.loadLibrary",

    // Accessibility abuse (overlay attacks, keylogging)
    "Landroid/accessibilityservice/",

    // SMS/telephony (premium SMS fraud)
    "Landroid/telephony/SmsManager",

    // Package manager (app enumeration, install)
    "Landroid/content/pm/PackageManager;.getInstalledPackages",
    "Landroid/content/pm/PackageManager;.getInstalledApplications",
};
static const int kTracePrefixCount = sizeof(kTracePrefixes) / sizeof(kTracePrefixes[0]);

// Check if a class signature matches any of the trace prefixes
static bool ShouldTrace(const char* class_sig, const char* method_name) {
    if (!class_sig) return false;

    // Build "Lcom/example/Class;.methodName" for prefix matching
    char full[640];
    if (method_name) {
        snprintf(full, sizeof(full), "%s.%s", class_sig, method_name);
    }

    for (int i = 0; i < kTracePrefixCount; i++) {
        // Match against class signature alone
        if (strncmp(class_sig, kTracePrefixes[i], strlen(kTracePrefixes[i])) == 0) {
            return true;
        }
        // Match against "class.method" for method-specific filters
        if (method_name &&
            strncmp(full, kTracePrefixes[i], strlen(kTracePrefixes[i])) == 0) {
            return true;
        }
    }
    return false;
}

// Helper: get class signature only (fast path for filtering)
static bool GetClassSig(jvmtiEnv* jvmti, jmethodID method,
                         char** out_class_sig, char** out_method_name) {
    jclass declaring_class = nullptr;
    jvmtiError err = jvmti->GetMethodDeclaringClass(method, &declaring_class);
    if (err != JVMTI_ERROR_NONE || declaring_class == nullptr) return false;

    err = jvmti->GetClassSignature(declaring_class, out_class_sig, nullptr);
    if (err != JVMTI_ERROR_NONE) return false;

    err = jvmti->GetMethodName(method, out_method_name, nullptr, nullptr);
    if (err != JVMTI_ERROR_NONE) {
        jvmti->Deallocate(reinterpret_cast<unsigned char*>(*out_class_sig));
        *out_class_sig = nullptr;
        return false;
    }
    return true;
}

// Helper: get fully-qualified method description
static void GetMethodDescription(jvmtiEnv* jvmti, jmethodID method,
                                  char* out, size_t out_len) {
    char* method_name = nullptr;
    char* method_sig = nullptr;
    char* class_sig = nullptr;
    jclass declaring_class = nullptr;

    jvmtiError err = jvmti->GetMethodName(method, &method_name, &method_sig, nullptr);
    if (err != JVMTI_ERROR_NONE) {
        snprintf(out, out_len, "<unknown method>");
        return;
    }

    err = jvmti->GetMethodDeclaringClass(method, &declaring_class);
    if (err == JVMTI_ERROR_NONE && declaring_class != nullptr) {
        jvmti->GetClassSignature(declaring_class, &class_sig, nullptr);
    }

    snprintf(out, out_len, "%s.%s%s",
             class_sig ? class_sig : "?",
             method_name ? method_name : "?",
             method_sig ? method_sig : "");

    if (method_name) jvmti->Deallocate(reinterpret_cast<unsigned char*>(method_name));
    if (method_sig) jvmti->Deallocate(reinterpret_cast<unsigned char*>(method_sig));
    if (class_sig) jvmti->Deallocate(reinterpret_cast<unsigned char*>(class_sig));
}

// ---------------------------------------------------------------------------
// Call recording: argument capture helpers
// ---------------------------------------------------------------------------

// Parse JNI method signature to count parameters.
// e.g. "(ILjava/lang/String;[B)V" → 3
static int CountSigParams(const char* sig) {
    if (!sig || *sig != '(') return 0;
    int count = 0;
    const char* p = sig + 1;
    while (*p && *p != ')') {
        if (*p == 'L') {
            // Object type: skip to ';'
            while (*p && *p != ';') p++;
            if (*p) p++;
        } else if (*p == '[') {
            // Array: skip '[' and continue to base type
            p++;
            continue;
        } else {
            // Primitive type: single char
            p++;
        }
        count++;
    }
    return count;
}

// Capture up to 4 argument values as strings for a call_entry record.
// Writes a JSON array string like ["ENCRYPT","key:0011...","data"] into out.
static void CaptureArgsSummary(jvmtiEnv* jvmti, JNIEnv* jni, jthread thread,
                                jmethodID method, const char* method_sig,
                                char* out, size_t out_len) {
    out[0] = '\0';
    if (!method_sig || !g_have_local_vars) return;

    int param_count = CountSigParams(method_sig);
    if (param_count == 0) {
        snprintf(out, out_len, "[]");
        return;
    }

    // Check if method is static (no 'this' parameter)
    jint modifiers = 0;
    bool is_static = false;
    if (jvmti->GetMethodModifiers(method, &modifiers) == JVMTI_ERROR_NONE) {
        is_static = (modifiers & 0x0008) != 0; // ACC_STATIC
    }

    // First param_idx: 0 = this for instance methods, skip to 1
    int first_arg = is_static ? 0 : 1;
    int max_args = param_count < 4 ? param_count : 4;

    // Build JSON array
    int pos = 0;
    pos += snprintf(out + pos, out_len - pos, "[");

    const char* p = method_sig + 1; // skip '('
    for (int i = 0; i < param_count && i < max_args; i++) {
        if (i > 0) pos += snprintf(out + pos, out_len - pos, ",");

        jint slot = GetParamSlot(jvmti, method, first_arg + i);
        if (slot < 0) {
            pos += snprintf(out + pos, out_len - pos, "\"?\"");
            // Skip this param type
            if (*p == 'L') { while (*p && *p != ';') p++; if (*p) p++; }
            else if (*p == '[') { p++; if (*p == 'L') { while (*p && *p != ';') p++; if (*p) p++; } else if (*p) p++; }
            else if (*p) p++;
            continue;
        }

        char val[256] = "?";
        switch (*p) {
            case 'I': {
                jint v = 0;
                if (jvmti->GetLocalInt(thread, 0, slot, &v) == JVMTI_ERROR_NONE)
                    snprintf(val, sizeof(val), "%d", v);
                p++;
                break;
            }
            case 'J': {
                jlong v = 0;
                if (jvmti->GetLocalLong(thread, 0, slot, &v) == JVMTI_ERROR_NONE)
                    snprintf(val, sizeof(val), "%lld", (long long)v);
                p++;
                break;
            }
            case 'Z': {
                jint v = 0;
                if (jvmti->GetLocalInt(thread, 0, slot, &v) == JVMTI_ERROR_NONE)
                    snprintf(val, sizeof(val), "%s", v ? "true" : "false");
                p++;
                break;
            }
            case 'F': {
                jfloat v = 0;
                if (jvmti->GetLocalFloat(thread, 0, slot, &v) == JVMTI_ERROR_NONE)
                    snprintf(val, sizeof(val), "%g", (double)v);
                p++;
                break;
            }
            case 'D': {
                jdouble v = 0;
                if (jvmti->GetLocalDouble(thread, 0, slot, &v) == JVMTI_ERROR_NONE)
                    snprintf(val, sizeof(val), "%g", v);
                p++;
                break;
            }
            case 'B': case 'S': case 'C': {
                jint v = 0;
                if (jvmti->GetLocalInt(thread, 0, slot, &v) == JVMTI_ERROR_NONE)
                    snprintf(val, sizeof(val), "%d", v);
                p++;
                break;
            }
            case 'L': {
                jobject obj = nullptr;
                if (jvmti->GetLocalObject(thread, 0, slot, &obj) == JVMTI_ERROR_NONE) {
                    FormatObjectValue(jni, obj, val, sizeof(val), false);
                    if (obj) jni->DeleteLocalRef(obj);
                }
                while (*p && *p != ';') p++;
                if (*p) p++;
                break;
            }
            case '[': {
                jobject obj = nullptr;
                if (jvmti->GetLocalObject(thread, 0, slot, &obj) == JVMTI_ERROR_NONE) {
                    FormatObjectValue(jni, obj, val, sizeof(val), false);
                    if (obj) jni->DeleteLocalRef(obj);
                }
                // Skip array type descriptor
                p++;
                if (*p == 'L') { while (*p && *p != ';') p++; if (*p) p++; }
                else if (*p) p++;
                break;
            }
            default:
                p++;
                break;
        }

        // JSON-escape the value and add as string
        pos += snprintf(out + pos, out_len - pos, "\"");
        for (int j = 0; val[j] && pos < (int)out_len - 8; j++) {
            unsigned char c = (unsigned char)val[j];
            if (c == '"' || c == '\\') {
                out[pos++] = '\\';
                out[pos++] = val[j];
            } else if (c == '\n') {
                out[pos++] = '\\'; out[pos++] = 'n';
            } else if (c == '\r') {
                out[pos++] = '\\'; out[pos++] = 'r';
            } else if (c == '\t') {
                out[pos++] = '\\'; out[pos++] = 't';
            } else if (c < 0x20) {
                pos += snprintf(out + pos, out_len - pos, "\\u%04x", c);
            } else {
                out[pos++] = val[j];
            }
        }
        pos += snprintf(out + pos, out_len - pos, "\"");
    }

    snprintf(out + pos, out_len - pos, "]");
}

// ---------------------------------------------------------------------------
// Callbacks
// ---------------------------------------------------------------------------

// Callback: thread ending — if this is the step thread, clean up immediately
// so the server doesn't stay stuck in STEPPING state waiting for a step event
// that will never come (e.g. stepped on return-void in threadTerminated).
static void JNICALL OnThreadEnd(
        jvmtiEnv* jvmti,
        JNIEnv* jni,
        jthread thread) {
    HandleStepThreadEnd(jvmti, jni, thread);
}

static void JNICALL OnThreadStart(
        jvmtiEnv* jvmti,
        JNIEnv* jni,
        jthread thread) {
    HandleThreadStart(jvmti, jni, thread);
}

// Callback: breakpoint hit — enter debugger command loop
static void JNICALL OnBreakpoint(
        jvmtiEnv* jvmti,
        JNIEnv* jni,
        jthread thread,
        jmethodID method,
        jlocation location) {
    int bp_id = FindBreakpointId(method, location);
    if (bp_id < 0) {
        // Unknown breakpoint — should not happen, but don't crash
        ALOGW("[DBG] OnBreakpoint for unknown bp at method=%p loc=%lld", method, (long long)location);
        return;
    }
    ALOGI("[DBG] Breakpoint #%d hit at loc=%lld", bp_id, (long long)location);
    DebuggerCommandLoop(jvmti, jni, thread, method, location, bp_id);
}

// Callback: single step — check if we should stop
static void JNICALL OnSingleStep(
        jvmtiEnv* jvmti,
        JNIEnv* jni,
        jthread thread,
        jmethodID method,
        jlocation location) {
    if (ShouldStopStepping(jvmti, jni, thread, method, location)) {
        ALOGI("[DBG] Step stopped at loc=%lld", (long long)location);
        DebuggerCommandLoop(jvmti, jni, thread, method, location, -1);
    }
}

// Callback: FramePop — fires when a method returns (after NotifyFramePop).
// Used by sout2 (fast step-out): runs at full speed, no single-step overhead.
static void JNICALL OnFramePop(
        jvmtiEnv* jvmti,
        JNIEnv* jni,
        jthread thread,
        jmethodID method,
        jboolean was_exception) {
    HandleFramePop(jvmti, jni, thread, method, was_exception);
}

// Callback: JIT compiled a method (only on userdebug/eng builds)
static void JNICALL OnCompiledMethodLoad(
        jvmtiEnv* jvmti,
        jmethodID method,
        jint code_size,
        const void* code_addr,
        jint map_length,
        const jvmtiAddrLocationMap* map,
        const void* compile_info) {
    char desc[512];
    GetMethodDescription(jvmti, method, desc, sizeof(desc));
    ALOGI("[JIT COMPILE] %s | %d bytes @ %p", desc, code_size, code_addr);
}

// Callback: JIT discarded compiled code
static void JNICALL OnCompiledMethodUnload(
        jvmtiEnv* jvmti,
        jmethodID method,
        const void* code_addr) {
    ALOGI("[JIT UNLOAD] method %p code @ %p", method, code_addr);
}

// Callback: filtered method entry — only logs security-relevant calls
static void JNICALL OnMethodEntry(
        jvmtiEnv* jvmti,
        JNIEnv* jni,
        jthread thread,
        jmethodID method) {
    char* class_sig = nullptr;
    char* method_name = nullptr;

    if (!GetClassSig(jvmti, method, &class_sig, &method_name)) return;

    if (ShouldTrace(class_sig, method_name)) {
        // DumpBytecodes(jvmti, method, class_sig, method_name);

        // Extract crypto keys, IVs, and data via JNI
        InspectCryptoCall(jvmti, jni, thread, method, class_sig, method_name);

        // Call recording: send call_entry when recording is active
        DebuggerState* dbg = GetDebuggerState();
        if (dbg->recording.load(std::memory_order_relaxed)) {
            // Rate limiting
            struct timespec ts;
            clock_gettime(CLOCK_MONOTONIC, &ts);
            long long epoch = ts.tv_sec;
            if (epoch != dbg->rate_limit_epoch) {
                dbg->rate_limit_epoch = epoch;
                dbg->calls_this_second = 0;
            }
            dbg->calls_this_second++;
            if (dbg->calls_this_second <= 500) {
                int seq = dbg->call_seq.fetch_add(1, std::memory_order_relaxed);

                // Get thread name
                jvmtiThreadInfo tinfo;
                memset(&tinfo, 0, sizeof(tinfo));
                jvmti->GetThreadInfo(thread, &tinfo);
                const char* tname = tinfo.name ? tinfo.name : "?";

                // Get method signature for arg capture
                char* method_sig = nullptr;
                jvmti->GetMethodName(method, nullptr, &method_sig, nullptr);

                // Capture argument values
                char args_json[2048] = "[]";
                if (method_sig) {
                    CaptureArgsSummary(jvmti, jni, thread, method, method_sig,
                                       args_json, sizeof(args_json));
                }

                // Get timestamp in milliseconds
                long long ts_ms = ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL;

                JsonBuf jb;
                json_start(&jb);
                json_add_string(&jb, "type", "call_entry");
                json_add_int(&jb, "seq", seq);
                json_add_long(&jb, "ts", ts_ms);
                json_add_string(&jb, "thread", tname);
                json_add_string(&jb, "class", class_sig);
                json_add_string(&jb, "method", method_name);
                if (method_sig) json_add_string(&jb, "sig", method_sig);
                json_add_raw(&jb, "args", args_json);
                json_end(&jb);
                SendToClient(jb.buf);

                if (tinfo.name) jvmti->Deallocate(reinterpret_cast<unsigned char*>(tinfo.name));
                if (method_sig) jvmti->Deallocate(reinterpret_cast<unsigned char*>(method_sig));
            } else if (dbg->calls_this_second == 501) {
                // Send overflow notification once per window
                JsonBuf jb;
                json_start(&jb);
                json_add_string(&jb, "type", "call_overflow");
                json_add_int(&jb, "dropped", 1);
                json_add_int(&jb, "window_ms", 1000);
                json_end(&jb);
                SendToClient(jb.buf);
            }
        }
    }

    jvmti->Deallocate(reinterpret_cast<unsigned char*>(class_sig));
    jvmti->Deallocate(reinterpret_cast<unsigned char*>(method_name));
}

// Callback: method exit — capture return values during recording
static void JNICALL OnMethodExit(
        jvmtiEnv* jvmti,
        JNIEnv* jni,
        jthread thread,
        jmethodID method,
        jboolean was_popped_by_exception,
        jvalue return_value) {
    DebuggerState* dbg = GetDebuggerState();
    if (!dbg->recording.load(std::memory_order_relaxed)) return;

    char* class_sig = nullptr;
    char* method_name = nullptr;
    if (!GetClassSig(jvmti, method, &class_sig, &method_name)) return;

    if (ShouldTrace(class_sig, method_name)) {
        // Rate limiting (share counter with entry)
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        long long epoch = ts.tv_sec;
        if (epoch != dbg->rate_limit_epoch) {
            dbg->rate_limit_epoch = epoch;
            dbg->calls_this_second = 0;
        }
        dbg->calls_this_second++;
        if (dbg->calls_this_second <= 500) {
            // Get thread name
            jvmtiThreadInfo tinfo;
            memset(&tinfo, 0, sizeof(tinfo));
            jvmti->GetThreadInfo(thread, &tinfo);
            const char* tname = tinfo.name ? tinfo.name : "?";

            // Get method signature to determine return type
            char* method_sig = nullptr;
            jvmti->GetMethodName(method, nullptr, &method_sig, nullptr);

            // Format return value
            char ret_str[256] = "";
            if (!was_popped_by_exception && method_sig) {
                // Find return type: everything after ')'
                const char* ret_type = strchr(method_sig, ')');
                if (ret_type) {
                    ret_type++; // skip ')'
                    switch (*ret_type) {
                        case 'V': // void — no return value
                            break;
                        case 'I':
                            snprintf(ret_str, sizeof(ret_str), "%d (0x%X)", return_value.i, (unsigned int)return_value.i);
                            break;
                        case 'J':
                            snprintf(ret_str, sizeof(ret_str), "%lld (0x%llX)", (long long)return_value.j, (unsigned long long)return_value.j);
                            break;
                        case 'Z':
                            snprintf(ret_str, sizeof(ret_str), "%s", return_value.z ? "true" : "false");
                            break;
                        case 'F':
                            snprintf(ret_str, sizeof(ret_str), "%g", (double)return_value.f);
                            break;
                        case 'D':
                            snprintf(ret_str, sizeof(ret_str), "%g", return_value.d);
                            break;
                        case 'B':
                            snprintf(ret_str, sizeof(ret_str), "%d", return_value.b);
                            break;
                        case 'S':
                            snprintf(ret_str, sizeof(ret_str), "%d", return_value.s);
                            break;
                        case 'C':
                            snprintf(ret_str, sizeof(ret_str), "'%c'", (char)return_value.c);
                            break;
                        case 'L': // object
                        case '[': // array
                            if (return_value.l) {
                                FormatObjectValue(jni, return_value.l, ret_str, sizeof(ret_str), false);
                            } else {
                                snprintf(ret_str, sizeof(ret_str), "null");
                            }
                            break;
                    }
                }
            }

            JsonBuf jb;
            json_start(&jb);
            json_add_string(&jb, "type", "call_exit");
            json_add_string(&jb, "thread", tname);
            json_add_string(&jb, "class", class_sig);
            json_add_string(&jb, "method", method_name);
            if (ret_str[0]) json_add_string(&jb, "ret", ret_str);
            json_add_bool(&jb, "exception", (bool)was_popped_by_exception);
            json_end(&jb);
            SendToClient(jb.buf);

            if (tinfo.name) jvmti->Deallocate(reinterpret_cast<unsigned char*>(tinfo.name));
            if (method_sig) jvmti->Deallocate(reinterpret_cast<unsigned char*>(method_sig));
        }
    }

    jvmti->Deallocate(reinterpret_cast<unsigned char*>(class_sig));
    jvmti->Deallocate(reinterpret_cast<unsigned char*>(method_name));
}

// Callback: exception thrown — log to logcat and forward over protocol
static void JNICALL OnException(
        jvmtiEnv* jvmti,
        JNIEnv* jni,
        jthread thread,
        jmethodID method,
        jlocation location,
        jobject exception,
        jmethodID catch_method,
        jlocation catch_location) {
    // Get throw site info
    char* class_sig = nullptr;
    char* method_name = nullptr;
    char* method_sig = nullptr;
    jclass declaring_class = nullptr;
    jvmti->GetMethodDeclaringClass(method, &declaring_class);
    if (declaring_class) jvmti->GetClassSignature(declaring_class, &class_sig, nullptr);
    jvmti->GetMethodName(method, &method_name, &method_sig, nullptr);

    // Get exception class name
    jclass exc_class = jni->GetObjectClass(exception);
    char* exc_sig = nullptr;
    jvmti->GetClassSignature(exc_class, &exc_sig, nullptr);

    ALOGI("[EXCEPTION] %s in %s.%s", exc_sig ? exc_sig : "?",
          class_sig ? class_sig : "?", method_name ? method_name : "?");

    // Forward over protocol
    {
        // Get catch site info (if caught)
        char* catch_class_sig = nullptr;
        char* catch_method_name = nullptr;
        if (catch_method) {
            jclass catch_class = nullptr;
            jvmti->GetMethodDeclaringClass(catch_method, &catch_class);
            if (catch_class) jvmti->GetClassSignature(catch_class, &catch_class_sig, nullptr);
            jvmti->GetMethodName(catch_method, &catch_method_name, nullptr, nullptr);
        }

        // Get exception message via Throwable.getMessage()
        char exc_msg[512] = "";
        jmethodID getMessage = jni->GetMethodID(exc_class, "getMessage", "()Ljava/lang/String;");
        if (!jni->ExceptionCheck() && getMessage) {
            jstring msg = (jstring)jni->CallObjectMethod(exception, getMessage);
            if (!jni->ExceptionCheck() && msg) {
                const char* s = jni->GetStringUTFChars(msg, nullptr);
                if (s) {
                    snprintf(exc_msg, sizeof(exc_msg), "%s", s);
                    jni->ReleaseStringUTFChars(msg, s);
                }
                jni->DeleteLocalRef(msg);
            }
        }
        if (jni->ExceptionCheck()) jni->ExceptionClear();

        JsonBuf jb;
        json_start(&jb);
        json_add_string(&jb, "type", "exception");
        json_add_string(&jb, "exception_class", exc_sig ? exc_sig : "?");
        json_add_string(&jb, "message", exc_msg);
        json_add_string(&jb, "class", class_sig ? class_sig : "?");
        json_add_string(&jb, "method", method_name ? method_name : "?");
        json_add_long(&jb, "location", (long long)location);
        json_add_bool(&jb, "caught", catch_method != nullptr);
        if (catch_class_sig)
            json_add_string(&jb, "catch_class", catch_class_sig);
        if (catch_method_name)
            json_add_string(&jb, "catch_method", catch_method_name);
        json_end(&jb);
        SendToClient(jb.buf);

        if (catch_class_sig) jvmti->Deallocate(reinterpret_cast<unsigned char*>(catch_class_sig));
        if (catch_method_name) jvmti->Deallocate(reinterpret_cast<unsigned char*>(catch_method_name));
    }

    if (exc_sig) jvmti->Deallocate(reinterpret_cast<unsigned char*>(exc_sig));
    if (class_sig) jvmti->Deallocate(reinterpret_cast<unsigned char*>(class_sig));
    if (method_name) jvmti->Deallocate(reinterpret_cast<unsigned char*>(method_name));
    if (method_sig) jvmti->Deallocate(reinterpret_cast<unsigned char*>(method_sig));
}

// Callback: class prepare — activate any deferred breakpoints on this class
static void JNICALL OnClassPrepare(
        jvmtiEnv* jvmti,
        JNIEnv* jni,
        jthread thread,
        jclass klass) {
    HandleClassPrepare(jvmti, jni, thread, klass);
}

// Callback: VM is shutting down
static void JNICALL OnVMDeath(jvmtiEnv* jvmti, JNIEnv* jni) {
    ALOGI("VM death — agent detaching");
}

// ---------------------------------------------------------------------------
// Capabilities and setup
// ---------------------------------------------------------------------------

static void LogPotentialCapabilities(jvmtiEnv* jvmti) {
    jvmtiCapabilities potential;
    memset(&potential, 0, sizeof(potential));
    jvmtiError err = jvmti->GetPotentialCapabilities(&potential);
    if (err != JVMTI_ERROR_NONE) {
        ALOGW("GetPotentialCapabilities failed: %d", err);
        return;
    }

    ALOGI("=== Available JVMTI Capabilities ===");
    ALOGI("  can_generate_compiled_method_load_events: %d", potential.can_generate_compiled_method_load_events);
    ALOGI("  can_generate_method_entry_events:         %d", potential.can_generate_method_entry_events);
    ALOGI("  can_generate_method_exit_events:          %d", potential.can_generate_method_exit_events);
    ALOGI("  can_get_line_numbers:                     %d", potential.can_get_line_numbers);
    ALOGI("  can_access_local_variables:               %d", potential.can_access_local_variables);
    ALOGI("  can_generate_single_step_events:          %d", potential.can_generate_single_step_events);
    ALOGI("  can_generate_breakpoint_events:           %d", potential.can_generate_breakpoint_events);
    ALOGI("  can_generate_exception_events:            %d", potential.can_generate_exception_events);
    ALOGI("  can_get_bytecodes:                        %d", potential.can_get_bytecodes);
    ALOGI("  can_tag_objects:                          %d", potential.can_tag_objects);
    ALOGI("  can_generate_all_class_hook_events:       %d", potential.can_generate_all_class_hook_events);
    ALOGI("  can_redefine_classes:                     %d", potential.can_redefine_classes);
    ALOGI("  can_retransform_classes:                  %d", potential.can_retransform_classes);
    ALOGI("================================");
}

// Core setup logic — shared between all entry points
static jint SetupJvmtiAgent(JavaVM* vm, const char* entry_point) {
    static std::atomic<bool> s_initialized{false};
    if (s_initialized.exchange(true)) {
        ALOGI("%s: agent already initialized, skipping", entry_point);
        return JNI_OK;
    }
    ALOGI("=== %s: starting JVMTI setup ===", entry_point);

    // Log Android version info for debugging compatibility issues
    {
        char sdk[8] = "", rel[16] = "", model[64] = "";
        __system_property_get("ro.build.version.sdk", sdk);
        __system_property_get("ro.build.version.release", rel);
        __system_property_get("ro.product.model", model);
        ALOGI("Device: %s, Android %s (API %s)", model, rel, sdk);
    }

    // 1. Obtain JVMTI environment — try 1.2 first, fall back to 1.0
    jvmtiEnv* jvmti = nullptr;
    jint jvmti_ver = JVMTI_VERSION_1_2;
    jint result = vm->GetEnv(reinterpret_cast<void**>(&jvmti), jvmti_ver);
    if (result != JNI_OK || jvmti == nullptr) {
        ALOGW("JVMTI 1.2 (0x%x) failed (result=%d), trying 1.0", jvmti_ver, result);
        jvmti_ver = JVMTI_VERSION_1_0;
        result = vm->GetEnv(reinterpret_cast<void**>(&jvmti), jvmti_ver);
    }
    if (result != JNI_OK || jvmti == nullptr) {
        ALOGE("Failed to get JVMTI env (result=%d)", result);
        return JNI_ERR;
    }
    ALOGI("Got JVMTI env OK (version: 0x%x)", jvmti_ver);

    // 2. Log what's available, then request only what we can get
    LogPotentialCapabilities(jvmti);

    jvmtiCapabilities potential;
    memset(&potential, 0, sizeof(potential));
    jvmti->GetPotentialCapabilities(&potential);

    jvmtiCapabilities caps;
    memset(&caps, 0, sizeof(caps));

    bool have_jit = false;
    bool have_method_entry = false;
    bool have_method_exit = false;
    bool have_exception = false;
    bool have_breakpoint = false;
    bool have_single_step = false;
    bool have_tag_objects = false;
    bool have_class_prepare = false;

    if (potential.can_generate_compiled_method_load_events) {
        caps.can_generate_compiled_method_load_events = 1;
        have_jit = true;
    }
    if (potential.can_get_line_numbers) {
        caps.can_get_line_numbers = 1;
    }
    if (potential.can_generate_method_entry_events) {
        caps.can_generate_method_entry_events = 1;
        have_method_entry = true;
    }
    if (potential.can_generate_method_exit_events) {
        caps.can_generate_method_exit_events = 1;
        have_method_exit = true;
    }
    if (potential.can_generate_exception_events) {
        caps.can_generate_exception_events = 1;
        have_exception = true;
    }
    if (potential.can_get_bytecodes) {
        caps.can_get_bytecodes = 1;
        g_have_bytecodes = true;
    }
    if (potential.can_access_local_variables) {
        caps.can_access_local_variables = 1;
        g_have_local_vars = true;
    }
    if (potential.can_generate_breakpoint_events) {
        caps.can_generate_breakpoint_events = 1;
        have_breakpoint = true;
    }
    if (potential.can_generate_single_step_events) {
        caps.can_generate_single_step_events = 1;
        have_single_step = true;
    }
    if (potential.can_tag_objects) {
        caps.can_tag_objects = 1;
        have_tag_objects = true;
    }
    if (potential.can_suspend) {
        caps.can_suspend = 1;
    }
    if (potential.can_force_early_return) {
        caps.can_force_early_return = 1;
    }
    if (potential.can_pop_frame) {
        caps.can_pop_frame = 1;
    }
    bool have_frame_pop = false;
    if (potential.can_generate_frame_pop_events) {
        caps.can_generate_frame_pop_events = 1;
        have_frame_pop = true;
    }
    if (potential.can_redefine_classes) {
        caps.can_redefine_classes = 1;
    }
    if (potential.can_retransform_classes) {
        caps.can_retransform_classes = 1;
    }
    // CLASS_PREPARE needs no capability — always available
    have_class_prepare = true;

    jvmtiError err = jvmti->AddCapabilities(&caps);
    if (err != JVMTI_ERROR_NONE) {
        ALOGE("AddCapabilities failed: %d", err);
        return JNI_ERR;
    }
    ALOGI("Capabilities added (jit=%d, entry=%d, exit=%d, exception=%d, bytecodes=%d, locals=%d, bp=%d, step=%d, tag=%d, redefine=%d, retransform=%d)",
          have_jit, have_method_entry, have_method_exit, have_exception, g_have_bytecodes, g_have_local_vars,
          have_breakpoint, have_single_step, have_tag_objects,
          (int)caps.can_redefine_classes, (int)caps.can_retransform_classes);

    // Create dump directory for bytecodes
    if (g_have_bytecodes) {
        mkdir(kDumpDir, 0777);
        ALOGI("Bytecode dump dir: %s", kDumpDir);
    }

    // 3. Set event callbacks
    jvmtiEventCallbacks callbacks;
    memset(&callbacks, 0, sizeof(callbacks));
    callbacks.VMDeath = OnVMDeath;

    if (have_jit) {
        callbacks.CompiledMethodLoad = OnCompiledMethodLoad;
        callbacks.CompiledMethodUnload = OnCompiledMethodUnload;
    }
    if (have_method_entry) {
        callbacks.MethodEntry = OnMethodEntry;
    }
    if (have_exception) {
        callbacks.Exception = OnException;
    }
    if (have_method_exit) {
        callbacks.MethodExit = OnMethodExit;
    }
    if (have_breakpoint) {
        callbacks.Breakpoint = OnBreakpoint;
    }
    if (have_single_step) {
        callbacks.SingleStep = OnSingleStep;
    }
    if (have_class_prepare) {
        callbacks.ClassPrepare = OnClassPrepare;
    }
    callbacks.ThreadEnd   = OnThreadEnd;
    callbacks.ThreadStart = OnThreadStart;
    if (have_frame_pop) {
        callbacks.FramePop = OnFramePop;
    }

    err = jvmti->SetEventCallbacks(&callbacks, sizeof(callbacks));
    if (err != JVMTI_ERROR_NONE) {
        ALOGE("SetEventCallbacks failed: %d", err);
        return JNI_ERR;
    }
    ALOGI("Callbacks set OK");

    // 4. Enable available events
    if (have_jit) {
        err = jvmti->SetEventNotificationMode(JVMTI_ENABLE,
                JVMTI_EVENT_COMPILED_METHOD_LOAD, nullptr);
        if (err != JVMTI_ERROR_NONE) {
            ALOGW("Enable COMPILED_METHOD_LOAD failed: %d", err);
        } else {
            ALOGI("COMPILED_METHOD_LOAD enabled OK");
        }

        err = jvmti->SetEventNotificationMode(JVMTI_ENABLE,
                JVMTI_EVENT_COMPILED_METHOD_UNLOAD, nullptr);
        if (err != JVMTI_ERROR_NONE) {
            ALOGW("Enable COMPILED_METHOD_UNLOAD failed: %d", err);
        } else {
            ALOGI("COMPILED_METHOD_UNLOAD enabled OK");
        }
    }

    if (have_method_entry) {
        err = jvmti->SetEventNotificationMode(JVMTI_ENABLE,
                JVMTI_EVENT_METHOD_ENTRY, nullptr);
        if (err != JVMTI_ERROR_NONE) {
            ALOGW("Enable METHOD_ENTRY failed: %d", err);
        } else {
            ALOGI("METHOD_ENTRY enabled OK (filtered: crypto/reflect/net/dex)");
        }
    }

    if (have_exception) {
        err = jvmti->SetEventNotificationMode(JVMTI_ENABLE,
                JVMTI_EVENT_EXCEPTION, nullptr);
        if (err != JVMTI_ERROR_NONE) {
            ALOGW("Enable EXCEPTION failed: %d", err);
        } else {
            ALOGI("EXCEPTION enabled OK");
        }
    }

    err = jvmti->SetEventNotificationMode(JVMTI_ENABLE,
            JVMTI_EVENT_VM_DEATH, nullptr);
    if (err != JVMTI_ERROR_NONE) {
        ALOGW("Enable VM_DEATH failed: %d", err);
    }

    err = jvmti->SetEventNotificationMode(JVMTI_ENABLE,
            JVMTI_EVENT_THREAD_END, nullptr);
    if (err != JVMTI_ERROR_NONE) {
        ALOGW("Enable THREAD_END failed: %d", err);
    } else {
        ALOGI("THREAD_END enabled OK");
    }

    err = jvmti->SetEventNotificationMode(JVMTI_ENABLE,
            JVMTI_EVENT_THREAD_START, nullptr);
    if (err != JVMTI_ERROR_NONE) {
        ALOGW("Enable THREAD_START failed: %d", err);
    } else {
        ALOGI("THREAD_START enabled OK");
    }

    if (have_class_prepare) {
        err = jvmti->SetEventNotificationMode(JVMTI_ENABLE,
                JVMTI_EVENT_CLASS_PREPARE, nullptr);
        if (err != JVMTI_ERROR_NONE) {
            ALOGW("Enable CLASS_PREPARE failed: %d", err);
        } else {
            ALOGI("CLASS_PREPARE enabled OK (for deferred breakpoints)");
        }
    }

    // 5. Retroactive JIT events
    if (have_jit) {
        ALOGI("Calling GenerateEvents...");
        err = jvmti->GenerateEvents(JVMTI_EVENT_COMPILED_METHOD_LOAD);
        if (err != JVMTI_ERROR_NONE) {
            ALOGW("GenerateEvents failed: %d", err);
        } else {
            ALOGI("GenerateEvents completed OK");
        }
    }

    // 6. Start debugger socket thread
    // (StartDebugger reads granted capabilities from JVMTI after its memset)
    StartDebugger(jvmti, vm);

    ALOGI("=== Agent setup complete via %s ===", entry_point);
    ALOGI("Tracing: %d filter prefixes active", kTracePrefixCount);
    return JNI_OK;
}

// Entry point for late-attach via `cmd activity attach-agent`
extern "C" JNIEXPORT jint JNICALL Agent_OnAttach(
        JavaVM* vm, char* options, void* reserved) {
    ALOGI("Agent_OnAttach called (options: %s)", options ? options : "none");
    return SetupJvmtiAgent(vm, "Agent_OnAttach");
}

// Entry point when loaded via System.loadLibrary()
extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved) {
    ALOGI("JNI_OnLoad called — attempting JVMTI setup");
    jint rc = SetupJvmtiAgent(vm, "JNI_OnLoad");
    if (rc != JNI_OK) {
        ALOGW("JVMTI setup failed (rc=%d), library loaded but tracing inactive", rc);
    }
    return JNI_VERSION_1_6;
}

// Locate a symbol in an already-loaded .so.
//
// Reads /proc/self/maps to get the load base and on-disk path, then parses
// the ELF file directly (pread).  File-based parsing uses prelink VAs which
// are unambiguous regardless of RELR relocations applied at load time.
// No dlopen/dlsym — immune to Android linker namespace isolation.
//
// Returns absolute VA of the symbol, or 0 if not found.
static uintptr_t find_sym_in_loaded_so(const char* lib_substr,
                                        const char* sym_name) {
    // 1. Find load base and file path from /proc/self/maps
    FILE* maps = fopen("/proc/self/maps", "r");
    if (!maps) {
        ALOGW("find_sym: can't open /proc/self/maps: %s", strerror(errno));
        return 0;
    }
    uintptr_t base = 0;
    char lib_path[512] = {};
    char line[640];
    while (fgets(line, sizeof(line), maps)) {
        if (!strstr(line, lib_substr)) continue;
        uintptr_t lo, hi; uint64_t foff; unsigned long inode;
        char perms[8], dev[16], path[512];
        int n = sscanf(line, "%lx-%lx %7s %lx %15s %lu %511s",
                       &lo, &hi, perms, &foff, dev, &inode, path);
        if (n < 7 || foff != 0) continue;
        base = lo;
        strncpy(lib_path, path, sizeof(lib_path) - 1);
        break;
    }
    fclose(maps);
    if (!base) {
        ALOGW("find_sym: '%s' not found in /proc/self/maps", lib_substr);
        return 0;
    }
    ALOGI("find_sym: '%s' base=0x%lx path=%s", lib_substr, base, lib_path);

    // 2. Open and parse ELF file (prelink VAs, no RELR ambiguity)
    int fd = open(lib_path, O_RDONLY);
    if (fd < 0) {
        ALOGW("find_sym: open('%s') failed: %s", lib_path, strerror(errno));
        return 0;
    }

    Elf64_Ehdr eh;
    if (pread(fd, &eh, sizeof(eh), 0) != sizeof(eh) ||
        memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0 ||
        eh.e_ident[EI_CLASS] != ELFCLASS64) {
        ALOGW("find_sym: not ELF64: %s", lib_path);
        close(fd); return 0;
    }

    int nph = (eh.e_phnum < 32) ? eh.e_phnum : 32;
    Elf64_Phdr phdrs[32];
    pread(fd, phdrs, nph * sizeof(Elf64_Phdr), eh.e_phoff);

    Elf64_Phdr loads[8]; int nloads = 0;
    uint64_t dyn_va = 0, dyn_filesz = 0;
    for (int i = 0; i < nph; i++) {
        if (phdrs[i].p_type == PT_LOAD && nloads < 8) loads[nloads++] = phdrs[i];
        if (phdrs[i].p_type == PT_DYNAMIC) {
            dyn_va    = phdrs[i].p_vaddr;
            dyn_filesz = phdrs[i].p_filesz;
        }
    }
    if (!dyn_va || !nloads) {
        ALOGW("find_sym: no PT_DYNAMIC in %s", lib_path);
        close(fd); return 0;
    }

    // Convert prelink VA → file offset
    auto va_to_off = [&](uint64_t va) -> uint64_t {
        for (int i = 0; i < nloads; i++)
            if (va >= loads[i].p_vaddr && va < loads[i].p_vaddr + loads[i].p_memsz)
                return loads[i].p_offset + (va - loads[i].p_vaddr);
        return (uint64_t)-1;
    };

    size_t ndyn = dyn_filesz / sizeof(Elf64_Dyn);
    Elf64_Dyn* dyn = (Elf64_Dyn*)malloc(dyn_filesz);
    if (!dyn || pread(fd, dyn, dyn_filesz, va_to_off(dyn_va)) != (ssize_t)dyn_filesz) {
        free(dyn); close(fd); return 0;
    }

    uint64_t symtab_va = 0, strtab_va = 0, strtab_sz = 0;
    uint64_t hash_va = 0, gnuhash_va = 0;
    for (size_t i = 0; i < ndyn; i++) {
        switch (dyn[i].d_tag) {
            case DT_SYMTAB:   symtab_va  = dyn[i].d_un.d_ptr; break;
            case DT_STRTAB:   strtab_va  = dyn[i].d_un.d_ptr; break;
            case DT_STRSZ:    strtab_sz  = dyn[i].d_un.d_val; break;
            case DT_HASH:     hash_va    = dyn[i].d_un.d_ptr; break;
            case DT_GNU_HASH: gnuhash_va = dyn[i].d_un.d_ptr; break;
        }
    }
    free(dyn);

    ALOGI("find_sym: symtab_va=0x%lx strtab_va=0x%lx strtab_sz=%lu gnuhash=%d hash=%d",
          symtab_va, strtab_va, strtab_sz, gnuhash_va != 0, hash_va != 0);

    if (!symtab_va || !strtab_va) { close(fd); return 0; }

    // Determine symbol count
    uint32_t nsyms = 65535;
    if (hash_va) {
        uint32_t hdr[2];
        uint64_t off = va_to_off(hash_va);
        if (off != (uint64_t)-1 && pread(fd, hdr, 8, off) == 8)
            nsyms = hdr[1];
    } else if (gnuhash_va) {
        uint32_t ghdr[4];
        uint64_t gh_off = va_to_off(gnuhash_va);
        if (gh_off != (uint64_t)-1 && pread(fd, ghdr, 16, gh_off) == 16) {
            uint32_t nb = ghdr[0], symoff = ghdr[1], bloom_sz = ghdr[2];
            uint64_t bkt_off = gh_off + 16 + (uint64_t)bloom_sz * 8;
            uint64_t chn_off = bkt_off + (uint64_t)nb * 4;
            uint32_t max_sym = symoff;
            uint32_t* bkts = (uint32_t*)malloc((size_t)nb * 4);
            if (bkts && pread(fd, bkts, nb * 4, bkt_off) == (ssize_t)(nb * 4))
                for (uint32_t k = 0; k < nb; k++)
                    if (bkts[k] > max_sym) max_sym = bkts[k];
            free(bkts);
            if (max_sym >= symoff) {
                uint32_t cidx = max_sym - symoff;
                for (;;) {
                    uint32_t c;
                    if (pread(fd, &c, 4, chn_off + (uint64_t)cidx * 4) != 4) break;
                    cidx++;
                    if (c & 1) break;
                }
                nsyms = symoff + cidx;
            }
        }
    }
    ALOGI("find_sym: nsyms=%u", nsyms);

    // Read string table
    if (!strtab_sz || strtab_sz > (2u << 20)) strtab_sz = 65536;
    char* strtab = (char*)malloc(strtab_sz + 1);
    uint64_t strtab_off = va_to_off(strtab_va);
    if (!strtab || strtab_off == (uint64_t)-1 ||
        pread(fd, strtab, strtab_sz, strtab_off) <= 0) {
        free(strtab); close(fd); return 0;
    }
    strtab[strtab_sz] = '\0';

    // Scan symbol table
    uint64_t symtab_off = va_to_off(symtab_va);
    size_t name_len = strlen(sym_name);
    uintptr_t result = 0;
    for (uint32_t i = 0; i < nsyms && !result; i++) {
        Elf64_Sym sym;
        if (pread(fd, &sym, sizeof(sym), symtab_off + i * sizeof(sym)) != sizeof(sym))
            break;
        if (!sym.st_value) continue;
        if (sym.st_name + name_len >= strtab_sz) continue;
        if (strncmp(strtab + sym.st_name, sym_name, name_len + 1) == 0) {
            result = base + sym.st_value;
            ALOGI("find_sym: '%s' prelink=0x%lx abs=0x%lx",
                  sym_name, (unsigned long)sym.st_value, (unsigned long)result);
        }
    }

    free(strtab);
    close(fd);
    return result;
}

// Root cause of GetEnv(JVMTI_VERSION) returning JNI_EVERSION(-3) on non-debuggable apps:
//
// JavaVMExt::HandleGetEnv iterates a plugin handler vector at JavaVMExt+0x170.
// For non-debuggable apps, ART never loads libopenjdkjvmti.so (it's loaded only
// via -Xplugin:libopenjdkjvmti or --attach-agent), so the vector is empty and
// HandleGetEnv always returns -3.
//
// Fix:
//   1. Load libopenjdkjvmti.so and call ArtPlugin_Initialize, which calls
//      JavaVMExt::AddEnvironmentHook(GetEnvHandler) to populate the vector.
//   2. Patch Runtime+0x534 (RuntimeDebugState) = 2 (kJavaDebuggable) so that
//      GetEnvHandler's own check passes and it creates a full JVMTI env.
//      (GetEnvHandler checks: runtime[0x330]==0 && runtime[0x534]!=2 → error;
//       we set +0x534=2 making the && false → success path.)
//
// NOTE: In this libart.so build, ArtPlugin_Initialize is called via `blr x0`
// where x0 = the fn ptr itself (no explicit arg setup before the call).
// This suggests it takes no external arguments on Android 14 and gets the VM
// via JNI_GetCreatedJavaVMs internally.

static void try_load_jvmti_plugin(JavaVM* vm) {
    // The app linker namespace (clns-4) blocks direct dlopen of APEX paths.
    // Use android_dlopen_ext with the exported ART namespace to bypass this.
    // ART exports its namespace so platform components can link to it.
    const char* kPath = "/apex/com.android.art/lib64/libopenjdkjvmti.so";

    void* handle = nullptr;

    // Try namespace-aware dlopen first.
    // android_get_exported_namespace lives in libdl_android.so (APEX), which is
    // not accessible via RTLD_DEFAULT from the app namespace.
    // Use our ELF scanner to find it by scanning /proc/self/maps directly.
    using get_ns_t     = android_namespace_t*(*)(const char*);
    using dlopen_ext_t = void*(*)(const char*, int, const android_dlextinfo*);
    auto get_ns = reinterpret_cast<get_ns_t>(
            find_sym_in_loaded_so("libdl_android.so", "android_get_exported_namespace"));
    auto dlopen_ext = reinterpret_cast<dlopen_ext_t>(
            dlsym(RTLD_DEFAULT, "android_dlopen_ext"));
    ALOGI("try_load_jvmti: get_ns=%p dlopen_ext=%p", get_ns, dlopen_ext);

    // The ART namespace may be exported as "com_android_art" or "art".
    if (get_ns && dlopen_ext) {
        const char* ns_names[] = { "com_android_art", "com.android.art", "art", nullptr };
        for (int i = 0; !handle && ns_names[i]; ++i) {
            android_namespace_t* art_ns = get_ns(ns_names[i]);
            if (!art_ns) {
                ALOGI("try_load_jvmti: namespace '%s' not found", ns_names[i]);
                continue;
            }
            android_dlextinfo extinfo = {};
            extinfo.flags = ANDROID_DLEXT_USE_NAMESPACE;
            extinfo.library_namespace = art_ns;
            // RTLD_LOCAL (not RTLD_GLOBAL) — RTLD_GLOBAL would leak libopenjdkjvmti
            // symbols into the global scope, which can corrupt entry points used by
            // concurrent Nterp threads (manifests as SIGSEGV in NterpCommonInvokeInstance).
            handle = dlopen_ext(kPath, RTLD_NOW | RTLD_LOCAL, &extinfo);
            ALOGI("try_load_jvmti: dlopen_ext(ns=%s art_ns=%p) -> handle=%p err=%s",
                  ns_names[i], art_ns, handle, handle ? "(none)" : dlerror());
        }
    } else {
        ALOGW("try_load_jvmti: ELF scan for get_ns failed (get_ns=%p dlopen_ext=%p)",
              get_ns, dlopen_ext);
    }

    // Fallback: plain dlopen (works if SELinux is permissive or namespace allows it).
    if (!handle) {
        handle = dlopen(kPath, RTLD_NOW | RTLD_LOCAL);
        ALOGI("try_load_jvmti: dlopen fallback -> handle=%p err=%s",
              handle, handle ? "(none)" : dlerror());
    }

    if (!handle) {
        ALOGW("try_load_jvmti: all dlopen attempts failed");
        return;
    }
    ALOGI("try_load_jvmti: loaded libopenjdkjvmti.so handle=%p", handle);

    // Try ArtPlugin_Initialize. Its exact signature depends on ART version:
    // - Older builds: takes (JavaVM*, bool*) or (JavaVMExt*, void*)
    // - Android 14 AOSP: takes no args (fetches VM internally)
    // - But Android 14 Pixel 7a binary may differ.
    // Pass vm + nullptr; if the function takes no args it ignores x0/x1.
    // If it takes JavaVM* as first arg, passing vm prevents a null deref.
    using ArtPluginInit_t = bool(*)(JavaVM*, void*);
    auto init_fn = reinterpret_cast<ArtPluginInit_t>(
            dlsym(handle, "ArtPlugin_Initialize"));
    if (!init_fn) {
        ALOGE("try_load_jvmti: ArtPlugin_Initialize not found: %s", dlerror());
        return;
    }

    // ArtPlugin_Initialize calls runtime->AddSystemWeakHolder() which uses
    // ScopedGCCriticalSection. The main thread (ptrace-injected ELF constructor)
    // is in kWaiting/kBlocked ART state (it was in a futex wait when interrupted).
    // Calling ART APIs that expect kRunnable/kNative from kWaiting crashes via
    // GC checkpoint dispatch in a Nterp thread.
    //
    // Fix: run ArtPlugin_Initialize from a fresh pthread that AttachCurrentThread
    // to the JVM — this gives it a valid kNative ART thread state.
    struct InitArgs {
        using fn_t = bool(*)(JavaVM*, void*);
        JavaVM* vm;
        fn_t init_fn;
        bool result;
    };
    static auto init_thread_fn = [](void* arg) -> void* {
        auto* a = static_cast<InitArgs*>(arg);
        JNIEnv* env = nullptr;
        a->vm->AttachCurrentThread(&env, nullptr);
        ALOGI("try_load_jvmti: [init thread] calling ArtPlugin_Initialize...");
        a->result = a->init_fn(a->vm, nullptr);
        ALOGI("try_load_jvmti: [init thread] ArtPlugin_Initialize returned %d",
              (int)a->result);
        a->vm->DetachCurrentThread();
        return nullptr;
    };

    InitArgs args = { vm, init_fn, false };
    pthread_t t;
    if (pthread_create(&t, nullptr, init_thread_fn, &args) != 0) {
        ALOGE("try_load_jvmti: pthread_create failed: %s", strerror(errno));
        return;
    }
    pthread_join(t, nullptr);
    ALOGI("try_load_jvmti: ArtPlugin_Initialize done (result=%d)", (int)args.result);
}

static bool patch_runtime_debuggable(JavaVM* vm) {
    // Patch Runtime+0x534 = 2 (kJavaDebuggable) so GetEnvHandler's condition:
    //   if (runtime[0x330]==0 && runtime[0x534]!=2) → error
    // evaluates to false → takes the success path → creates full JVMTI env.
    void* runtime = *reinterpret_cast<void**>(
            reinterpret_cast<uintptr_t>(vm) + 8u);
    if (!runtime) {
        ALOGE("patch_debuggable: runtime_ at vm+8 is null");
        return false;
    }

    auto* field534 = reinterpret_cast<uint32_t*>(
            reinterpret_cast<uintptr_t>(runtime) + 0x534u);
    ALOGI("patch_debuggable: vm=%p runtime=%p  RuntimeDebugState[+0x534]=%u -> 2",
          vm, runtime, *field534);
    *field534 = 2u;   // kJavaDebuggable
    __sync_synchronize();

    // Also patch is_native_debuggable_ at +0x52e (belt-and-suspenders).
    auto* field52e = reinterpret_cast<uint8_t*>(
            reinterpret_cast<uintptr_t>(runtime) + 0x52eu);
    ALOGI("patch_debuggable: is_native_debuggable_[+0x52e]=%d -> 1", (int)*field52e);
    *field52e = 1u;
    __sync_synchronize();

    return true;
}

// Entry point when loaded via bare dlopen() (ptrace injection).
// bionic calls ELF constructors on dlopen() but does NOT call JNI_OnLoad.
// This constructor finds the already-running JVM and calls JNI_OnLoad itself.
__attribute__((constructor))
static void agent_dlopen_constructor() {
    using GetVMs_t = jint(*)(JavaVM**, jsize, jsize*);
    GetVMs_t get_vms = nullptr;

    // Try RTLD_DEFAULT first (works if libart is in the caller's namespace).
    get_vms = reinterpret_cast<GetVMs_t>(
            dlsym(RTLD_DEFAULT, "JNI_GetCreatedJavaVMs"));

    // Android 10+: libart lives in the ART APEX namespace.
    // RTLD_NOLOAD returns a handle only if the lib is in *this* namespace;
    // on non-debuggable apps it typically fails due to namespace isolation.
    if (!get_vms) {
        void* h = dlopen("/apex/com.android.art/lib64/libart.so",
                         RTLD_LAZY | RTLD_NOLOAD);
        if (!h) h = dlopen("libart.so", RTLD_LAZY | RTLD_NOLOAD);
        if (h) {
            get_vms = reinterpret_cast<GetVMs_t>(
                    dlsym(h, "JNI_GetCreatedJavaVMs"));
            dlclose(h);
        }
    }

    // Last resort: bypass the linker entirely.  Walk /proc/self/maps to find
    // libart.so's load base, then scan its in-memory ELF .dynsym directly.
    // This is immune to namespace isolation — no dlopen/dlsym involved.
    if (!get_vms) {
        uintptr_t va = find_sym_in_loaded_so("libart.so", "JNI_GetCreatedJavaVMs");
        if (va) {
            get_vms = reinterpret_cast<GetVMs_t>(va);
            __android_log_print(ANDROID_LOG_INFO, "ArtJitTracer",
                    "agent_dlopen_constructor: found JNI_GetCreatedJavaVMs "
                    "via ELF scan at 0x%lx", (unsigned long)va);
        }
    }

    if (!get_vms) {
        __android_log_print(ANDROID_LOG_WARN, "ArtJitTracer",
                "agent_dlopen_constructor: JNI_GetCreatedJavaVMs not found");
        return;
    }

    JavaVM* vm_list[1];
    jsize count = 0;
    if (get_vms(vm_list, 1, &count) == JNI_OK && count > 0) {
        __android_log_print(ANDROID_LOG_INFO, "ArtJitTracer",
                "agent_dlopen_constructor: JVM found, bootstrapping agent");

        // For non-debuggable apps:
        //   1. Load libopenjdkjvmti.so + call ArtPlugin_Initialize to register
        //      GetEnvHandler in JavaVMExt+0x170 (the handler vector is empty
        //      without this — HandleGetEnv returns -3 immediately).
        //   2. Patch Runtime+0x534 (kJavaDebuggable) so GetEnvHandler's own
        //      condition passes and it creates a full JVMTI env.
        try_load_jvmti_plugin(vm_list[0]);
        patch_runtime_debuggable(vm_list[0]);

        JNI_OnLoad(vm_list[0], nullptr);
    } else {
        __android_log_print(ANDROID_LOG_WARN, "ArtJitTracer",
                "agent_dlopen_constructor: JVM not ready (count=%d)", (int)count);
    }
}
