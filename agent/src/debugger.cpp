#include "debugger.h"
#include "protocol.h"

#include <jni.h>
#include <jvmti.h>
#include <android/log.h>
#include <cstdio>
#include <cstdarg>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <stddef.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <pthread.h>
#include <sys/system_properties.h>

#define LOG_TAG "ArtJitTracer"
#define ALOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define ALOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)
#define ALOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// Use abstract Unix socket — SELinux blocks AF_INET for untrusted apps.
// Connect via: adb forward tcp:12345 localabstract:dexbgd
static const char* kSocketName = "dexbgd";

// Forward declaration — handles global commands (bp_set, cls, etc.)
static void DispatchGlobalCommand(jvmtiEnv* jvmti, JNIEnv* jni,
                                   const char* cmd, const char* json);

// ---------------------------------------------------------------------------
// Global debugger state
// ---------------------------------------------------------------------------

static DebuggerState g_dbg;

// Breakpoints deferred because their class was not loaded at bp_set time.
// Protected by g_pending_mu. Activated in HandleClassPrepare when CLASS_PREPARE fires.
static std::vector<PendingBreakpoint> g_pending_bps;
static pthread_mutex_t g_pending_mu = PTHREAD_MUTEX_INITIALIZER;

DebuggerState* GetDebuggerState() {
    return &g_dbg;
}

// ---------------------------------------------------------------------------
// Step thread management — store as global JNI ref so it survives callbacks
// ---------------------------------------------------------------------------

static void SetStepThread(JNIEnv* jni, jthread thread) {
    if (g_dbg.step_thread) {
        jni->DeleteGlobalRef(g_dbg.step_thread);
        g_dbg.step_thread = nullptr;
    }
    if (thread) {
        g_dbg.step_thread = (jthread)jni->NewGlobalRef(thread);
    }
}

static void ClearStepThread(JNIEnv* jni) {
    if (g_dbg.step_thread) {
        jni->DeleteGlobalRef(g_dbg.step_thread);
        g_dbg.step_thread = nullptr;
    }
}

// ---------------------------------------------------------------------------
// SendToClient — thread-safe write to connected client
// ---------------------------------------------------------------------------

void SendToClient(const char* json) {
    pthread_mutex_lock(&g_dbg.sock_mutex);
    int fd = g_dbg.client_fd;
    if (fd >= 0) {
        int len = strlen(json);
        int sent = 0;
        while (sent < len) {
            int n = send(fd, json + sent, len - sent, MSG_NOSIGNAL);
            if (n <= 0) {
                ALOGW("[DBG] send failed: %s", strerror(errno));
                break;
            }
            sent += n;
        }
    }
    pthread_mutex_unlock(&g_dbg.sock_mutex);
}

// ---------------------------------------------------------------------------
// Helper: send an error message to the client with printf-style formatting
// ---------------------------------------------------------------------------

static void SendError(const char* fmt, ...) {
    char msg[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    JsonBuf jb;
    json_start(&jb);
    json_add_string(&jb, "type", "error");
    json_add_string(&jb, "msg", msg);
    json_end(&jb);
    SendToClient(jb.buf);
}

// ---------------------------------------------------------------------------
// Helper: get JNIEnv for current thread
// ---------------------------------------------------------------------------

static JNIEnv* GetJNIEnv() {
    JNIEnv* jni = nullptr;
    g_dbg.vm->GetEnv(reinterpret_cast<void**>(&jni), JNI_VERSION_1_6);
    return jni;
}

// ---------------------------------------------------------------------------
// Helper: get method info strings. Caller must Deallocate returned strings.
// ---------------------------------------------------------------------------

static bool GetMethodInfo(jvmtiEnv* jvmti, jmethodID method,
                          char** out_class_sig, char** out_name, char** out_sig) {
    *out_class_sig = nullptr;
    *out_name = nullptr;
    *out_sig = nullptr;

    jclass klass = nullptr;
    if (jvmti->GetMethodDeclaringClass(method, &klass) != JVMTI_ERROR_NONE) return false;
    if (jvmti->GetClassSignature(klass, out_class_sig, nullptr) != JVMTI_ERROR_NONE) return false;
    if (jvmti->GetMethodName(method, out_name, out_sig, nullptr) != JVMTI_ERROR_NONE) {
        jvmti->Deallocate(reinterpret_cast<unsigned char*>(*out_class_sig));
        *out_class_sig = nullptr;
        return false;
    }
    return true;
}

static void FreeMethodInfo(jvmtiEnv* jvmti, char* class_sig, char* name, char* sig) {
    if (class_sig) jvmti->Deallocate(reinterpret_cast<unsigned char*>(class_sig));
    if (name) jvmti->Deallocate(reinterpret_cast<unsigned char*>(name));
    if (sig) jvmti->Deallocate(reinterpret_cast<unsigned char*>(sig));
}

// ---------------------------------------------------------------------------
// Helper: map jlocation to source line number. Returns -1 if unavailable.
// ---------------------------------------------------------------------------

static int LocationToLine(jvmtiEnv* jvmti, jmethodID method, jlocation loc) {
    jint count = 0;
    jvmtiLineNumberEntry* table = nullptr;
    if (jvmti->GetLineNumberTable(method, &count, &table) != JVMTI_ERROR_NONE || count == 0)
        return -1;

    int line = -1;
    for (int i = 0; i < count; i++) {
        if (table[i].start_location <= loc) {
            line = table[i].line_number;
        } else {
            break;
        }
    }
    jvmti->Deallocate(reinterpret_cast<unsigned char*>(table));
    return line;
}

// ---------------------------------------------------------------------------
// Milestone 1: Global commands (run on socket thread)
// ---------------------------------------------------------------------------

// cls: search loaded classes by pattern
static void CmdClasses(jvmtiEnv* jvmti, JNIEnv* jni, const char* json) {
    char pattern[256] = "";
    json_get_string(json, "pattern", pattern, sizeof(pattern));

    // Convert dots to slashes for JNI signature matching
    for (int i = 0; pattern[i]; i++) {
        if (pattern[i] == '.') pattern[i] = '/';
    }

    jint class_count = 0;
    jclass* classes = nullptr;
    jvmtiError err = jvmti->GetLoadedClasses(&class_count, &classes);
    if (err != JVMTI_ERROR_NONE) {
        JsonBuf jb;
        json_start(&jb);
        json_add_string(&jb, "type", "error");
        json_add_string(&jb, "msg", "GetLoadedClasses failed");
        json_end(&jb);
        SendToClient(jb.buf);
        return;
    }

    JsonArrayBuf ab;
    json_array_start(&ab);
    int match_count = 0;

    // Cap results to avoid overflowing the 16KB JsonArrayBuf.
    // Each entry is ~80 bytes JSON; 16KB / 80 ≈ 200 max safe entries.
    static const int MAX_CLS_RESULTS = 150;

    jni->PushLocalFrame(256);
    for (int i = 0; i < class_count; i++) {
        char* sig = nullptr;
        if (jvmti->GetClassSignature(classes[i], &sig, nullptr) == JVMTI_ERROR_NONE && sig) {
            if (pattern[0] == '\0' || strstr(sig, pattern)) {
                if (match_count < MAX_CLS_RESULTS) {
                    // Build a small object for this class
                    JsonBuf obj;
                    json_start(&obj);
                    json_add_string(&obj, "sig", sig);
                    json_end(&obj);
                    // Strip trailing \n so it can be embedded in array
                    obj.buf[obj.pos - 1] = '\0';
                    obj.pos -= 1;
                    json_array_add_object(&ab, obj.buf);
                }
                match_count++;
            }
            jvmti->Deallocate(reinterpret_cast<unsigned char*>(sig));
        }
        // Delete local ref every iteration to avoid overflow
        jni->DeleteLocalRef(classes[i]);
    }
    jni->PopLocalFrame(nullptr);
    jvmti->Deallocate(reinterpret_cast<unsigned char*>(classes));

    json_array_end(&ab);

    JsonBuf jb;
    json_start(&jb);
    json_add_string(&jb, "type", "cls_result");
    json_add_int(&jb, "count", match_count);
    json_add_raw(&jb, "classes", ab.buf);
    json_end(&jb);
    SendToClient(jb.buf);
}

// Helper: find a jclass by JNI signature (e.g. "Lcom/test/jitdemo/MainActivity;")
static jclass FindClassBySig(jvmtiEnv* jvmti, JNIEnv* jni, const char* target_sig) {
    jint class_count = 0;
    jclass* classes = nullptr;
    if (jvmti->GetLoadedClasses(&class_count, &classes) != JVMTI_ERROR_NONE)
        return nullptr;

    // Build suffix for short-name matching: "LMainActivity;" -> "/MainActivity;"
    // so that "Lcom/test/jitdemo/MainActivity;" is found by partial name.
    char suffix[258] = {};
    size_t tlen = strlen(target_sig);
    bool try_suffix = (tlen >= 3 && target_sig[0] == 'L' && target_sig[tlen - 1] == ';');
    if (try_suffix) {
        suffix[0] = '/';
        memcpy(suffix + 1, target_sig + 1, tlen - 1);  // "/MainActivty;"
        suffix[tlen] = '\0';
    }

    jclass found = nullptr;
    for (int i = 0; i < class_count; i++) {
        char* sig = nullptr;
        if (jvmti->GetClassSignature(classes[i], &sig, nullptr) == JVMTI_ERROR_NONE && sig) {
            if (strcmp(sig, target_sig) == 0) {
                found = (jclass)jni->NewGlobalRef(classes[i]);
            } else if (try_suffix && !found) {
                size_t slen = strlen(sig);
                size_t suflen = tlen; // "/Name;" is tlen chars (replacing leading 'L' with '/')
                if (slen > suflen) {
                    const char* tail = sig + slen - suflen;
                    if (strcmp(tail, suffix) == 0) {
                        found = (jclass)jni->NewGlobalRef(classes[i]);
                    }
                }
            }
            jvmti->Deallocate(reinterpret_cast<unsigned char*>(sig));
        }
        jni->DeleteLocalRef(classes[i]);
        if (found) break;
    }
    jvmti->Deallocate(reinterpret_cast<unsigned char*>(classes));
    return found;
}

// Helper: find a method by name (and optional signature) in a class
static jmethodID FindMethodInClass(jvmtiEnv* jvmti, jclass klass,
                                   const char* target_name, const char* target_sig) {
    jint method_count = 0;
    jmethodID* methods = nullptr;
    if (jvmti->GetClassMethods(klass, &method_count, &methods) != JVMTI_ERROR_NONE)
        return nullptr;

    jmethodID found = nullptr;
    for (int i = 0; i < method_count; i++) {
        char* name = nullptr;
        char* sig = nullptr;
        if (jvmti->GetMethodName(methods[i], &name, &sig, nullptr) == JVMTI_ERROR_NONE) {
            bool name_match = (strcmp(name, target_name) == 0);
            bool sig_match = (!target_sig || target_sig[0] == '\0' || strcmp(sig, target_sig) == 0);
            if (name_match && sig_match) {
                found = methods[i];
            }
            if (name) jvmti->Deallocate(reinterpret_cast<unsigned char*>(name));
            if (sig) jvmti->Deallocate(reinterpret_cast<unsigned char*>(sig));
        }
        if (found) break;
    }
    jvmti->Deallocate(reinterpret_cast<unsigned char*>(methods));
    return found;
}

// methods: list methods of a class
static void CmdMethods(jvmtiEnv* jvmti, JNIEnv* jni, const char* json) {
    char class_sig[256];
    if (!json_get_string(json, "class", class_sig, sizeof(class_sig))) {
        JsonBuf jb;
        json_start(&jb);
        json_add_string(&jb, "type", "error");
        json_add_string(&jb, "msg", "missing 'class' param");
        json_end(&jb);
        SendToClient(jb.buf);
        return;
    }

    jclass klass = FindClassBySig(jvmti, jni, class_sig);
    if (!klass) {
        JsonBuf jb;
        json_start(&jb);
        json_add_string(&jb, "type", "error");
        json_add_string(&jb, "msg", "class not found");
        json_end(&jb);
        SendToClient(jb.buf);
        return;
    }

    jint method_count = 0;
    jmethodID* methods = nullptr;
    jvmti->GetClassMethods(klass, &method_count, &methods);

    JsonArrayBuf ab;
    json_array_start(&ab);

    for (int i = 0; i < method_count; i++) {
        char* name = nullptr;
        char* sig = nullptr;
        jint modifiers = 0;
        jvmti->GetMethodName(methods[i], &name, &sig, nullptr);
        jvmti->GetMethodModifiers(methods[i], &modifiers);

        JsonBuf obj;
        json_start(&obj);
        json_add_string(&obj, "name", name ? name : "?");
        json_add_string(&obj, "sig", sig ? sig : "?");
        json_add_int(&obj, "modifiers", modifiers);
        json_end(&obj);
        obj.buf[obj.pos - 1] = '\0';
        obj.pos -= 1;
        json_array_add_object(&ab, obj.buf);

        if (name) jvmti->Deallocate(reinterpret_cast<unsigned char*>(name));
        if (sig) jvmti->Deallocate(reinterpret_cast<unsigned char*>(sig));
    }
    jvmti->Deallocate(reinterpret_cast<unsigned char*>(methods));
    jni->DeleteGlobalRef(klass);

    json_array_end(&ab);

    JsonBuf jb;
    json_start(&jb);
    json_add_string(&jb, "type", "methods_result");
    json_add_string(&jb, "class", class_sig);
    json_add_int(&jb, "count", method_count);
    json_add_raw(&jb, "methods", ab.buf);
    json_end(&jb);
    SendToClient(jb.buf);
}

// fields: list fields of a class
static void CmdFields(jvmtiEnv* jvmti, JNIEnv* jni, const char* json) {
    char class_sig[256];
    if (!json_get_string(json, "class", class_sig, sizeof(class_sig))) {
        JsonBuf jb;
        json_start(&jb);
        json_add_string(&jb, "type", "error");
        json_add_string(&jb, "msg", "missing 'class' param");
        json_end(&jb);
        SendToClient(jb.buf);
        return;
    }

    jclass klass = FindClassBySig(jvmti, jni, class_sig);
    if (!klass) {
        JsonBuf jb;
        json_start(&jb);
        json_add_string(&jb, "type", "error");
        json_add_string(&jb, "msg", "class not found");
        json_end(&jb);
        SendToClient(jb.buf);
        return;
    }

    jint field_count = 0;
    jfieldID* fields = nullptr;
    jvmti->GetClassFields(klass, &field_count, &fields);

    JsonArrayBuf ab;
    json_array_start(&ab);

    for (int i = 0; i < field_count; i++) {
        char* name = nullptr;
        char* sig = nullptr;
        jint modifiers = 0;
        jvmti->GetFieldName(klass, fields[i], &name, &sig, nullptr);
        jvmti->GetFieldModifiers(klass, fields[i], &modifiers);

        JsonBuf obj;
        json_start(&obj);
        json_add_string(&obj, "name", name ? name : "?");
        json_add_string(&obj, "sig", sig ? sig : "?");
        json_add_int(&obj, "modifiers", modifiers);
        json_end(&obj);
        obj.buf[obj.pos - 1] = '\0';
        obj.pos -= 1;
        json_array_add_object(&ab, obj.buf);

        if (name) jvmti->Deallocate(reinterpret_cast<unsigned char*>(name));
        if (sig) jvmti->Deallocate(reinterpret_cast<unsigned char*>(sig));
    }
    jvmti->Deallocate(reinterpret_cast<unsigned char*>(fields));
    jni->DeleteGlobalRef(klass);

    json_array_end(&ab);

    JsonBuf jb;
    json_start(&jb);
    json_add_string(&jb, "type", "fields_result");
    json_add_string(&jb, "class", class_sig);
    json_add_int(&jb, "count", field_count);
    json_add_raw(&jb, "fields", ab.buf);
    json_end(&jb);
    SendToClient(jb.buf);
}

// threads: list all threads
static void CmdThreads(jvmtiEnv* jvmti, JNIEnv* jni, const char* json) {
    jint thread_count = 0;
    jthread* threads = nullptr;
    if (jvmti->GetAllThreads(&thread_count, &threads) != JVMTI_ERROR_NONE) {
        JsonBuf jb;
        json_start(&jb);
        json_add_string(&jb, "type", "error");
        json_add_string(&jb, "msg", "GetAllThreads failed");
        json_end(&jb);
        SendToClient(jb.buf);
        return;
    }

    JsonArrayBuf ab;
    json_array_start(&ab);

    for (int i = 0; i < thread_count; i++) {
        jvmtiThreadInfo info;
        memset(&info, 0, sizeof(info));
        if (jvmti->GetThreadInfo(threads[i], &info) == JVMTI_ERROR_NONE) {
            JsonBuf obj;
            json_start(&obj);
            json_add_string(&obj, "name", info.name ? info.name : "?");
            json_add_int(&obj, "priority", info.priority);
            json_add_bool(&obj, "daemon", info.is_daemon);
            json_end(&obj);
            obj.buf[obj.pos - 1] = '\0';
            obj.pos -= 1;
            json_array_add_object(&ab, obj.buf);

            if (info.name) jvmti->Deallocate(reinterpret_cast<unsigned char*>(info.name));
        }
        jni->DeleteLocalRef(threads[i]);
    }
    jvmti->Deallocate(reinterpret_cast<unsigned char*>(threads));

    json_array_end(&ab);

    JsonBuf jb;
    json_start(&jb);
    json_add_string(&jb, "type", "threads_result");
    json_add_int(&jb, "count", thread_count);
    json_add_raw(&jb, "threads", ab.buf);
    json_end(&jb);
    SendToClient(jb.buf);
}

// dis: disassemble a method (return base64-encoded bytecodes)
static void CmdDisassemble(jvmtiEnv* jvmti, JNIEnv* jni, const char* json) {
    if (!g_dbg.cap_bytecodes) {
        SendError("GetBytecodes not available on this device/Android version");
        return;
    }
    char class_sig[256], method_name[128], method_sig[256];
    if (!json_get_string(json, "class", class_sig, sizeof(class_sig)) ||
        !json_get_string(json, "method", method_name, sizeof(method_name))) {
        JsonBuf jb;
        json_start(&jb);
        json_add_string(&jb, "type", "error");
        json_add_string(&jb, "msg", "missing 'class' or 'method' param");
        json_end(&jb);
        SendToClient(jb.buf);
        return;
    }
    method_sig[0] = '\0';
    json_get_string(json, "sig", method_sig, sizeof(method_sig));

    jclass klass = FindClassBySig(jvmti, jni, class_sig);
    if (!klass) {
        JsonBuf jb;
        json_start(&jb);
        json_add_string(&jb, "type", "error");
        json_add_string(&jb, "msg", "class not found");
        json_end(&jb);
        SendToClient(jb.buf);
        return;
    }

    jmethodID mid = FindMethodInClass(jvmti, klass, method_name,
                                      method_sig[0] ? method_sig : nullptr);
    if (!mid) {
        jni->DeleteGlobalRef(klass);
        JsonBuf jb;
        json_start(&jb);
        json_add_string(&jb, "type", "error");
        json_add_string(&jb, "msg", "method not found");
        json_end(&jb);
        SendToClient(jb.buf);
        return;
    }

    jint bytecode_count = 0;
    unsigned char* bytecodes = nullptr;
    jvmtiError err = jvmti->GetBytecodes(mid, &bytecode_count, &bytecodes);
    jni->DeleteGlobalRef(klass);

    if (err != JVMTI_ERROR_NONE || !bytecodes) {
        SendError("GetBytecodes failed (err=%d) — method may be native or abstract", err);
        return;
    }

    // Base64 encode
    int b64_len = ((bytecode_count + 2) / 3) * 4 + 1;
    char* b64 = new char[b64_len];
    base64_encode(bytecodes, bytecode_count, b64, b64_len);
    jvmti->Deallocate(bytecodes);

    JsonBuf jb;
    json_start(&jb);
    json_add_string(&jb, "type", "dis_result");
    json_add_string(&jb, "class", class_sig);
    json_add_string(&jb, "method", method_name);
    json_add_int(&jb, "bytecode_len", bytecode_count);
    json_add_string(&jb, "bytecodes_b64", b64);
    json_end(&jb);
    SendToClient(jb.buf);

    delete[] b64;
}

// ---------------------------------------------------------------------------
// Milestone 2: Breakpoint commands (global, run on socket thread)
// ---------------------------------------------------------------------------

// bp_set: set a breakpoint on a method (at location 0 or specified location)
static void CmdBpSet(jvmtiEnv* jvmti, JNIEnv* jni, const char* json) {
    if (!g_dbg.cap_breakpoints) {
        SendError("Breakpoints not available on this device/Android version");
        return;
    }
    char class_sig[256], method_name[128], method_sig[256];
    if (!json_get_string(json, "class", class_sig, sizeof(class_sig)) ||
        !json_get_string(json, "method", method_name, sizeof(method_name))) {
        JsonBuf jb;
        json_start(&jb);
        json_add_string(&jb, "type", "error");
        json_add_string(&jb, "msg", "missing 'class' or 'method' param");
        json_end(&jb);
        SendToClient(jb.buf);
        return;
    }
    method_sig[0] = '\0';
    json_get_string(json, "sig", method_sig, sizeof(method_sig));

    long long loc_val = 0;
    json_get_long(json, "location", &loc_val);
    jlocation location = (jlocation)loc_val;

    jclass klass = FindClassBySig(jvmti, jni, class_sig);
    if (!klass) {
        // Class not yet loaded — queue for deferred activation via CLASS_PREPARE.
        int deferred_id;
        {
            pthread_mutex_lock(&g_pending_mu);
            deferred_id = g_dbg.next_bp_id++;
            PendingBreakpoint pbp;
            pbp.bp_id = deferred_id;
            strncpy(pbp.class_sig, class_sig, sizeof(pbp.class_sig) - 1);
            pbp.class_sig[sizeof(pbp.class_sig) - 1] = '\0';
            strncpy(pbp.method_name, method_name, sizeof(pbp.method_name) - 1);
            pbp.method_name[sizeof(pbp.method_name) - 1] = '\0';
            strncpy(pbp.method_sig, method_sig, sizeof(pbp.method_sig) - 1);
            pbp.method_sig[sizeof(pbp.method_sig) - 1] = '\0';
            g_pending_bps.push_back(pbp);
            pthread_mutex_unlock(&g_pending_mu);
        }
        ALOGI("[DBG] BP#%d deferred (class not loaded): %s.%s", deferred_id, class_sig, method_name);
        JsonBuf jb;
        json_start(&jb);
        json_add_string(&jb, "type", "bp_deferred");
        json_add_int(&jb, "id", deferred_id);
        json_add_string(&jb, "class", class_sig);
        json_add_string(&jb, "method", method_name);
        json_end(&jb);
        SendToClient(jb.buf);
        return;
    }

    // If a specific signature was given, find that one method.
    // Otherwise, find ALL overloads and set a breakpoint on each.
    if (method_sig[0]) {
        jmethodID mid = FindMethodInClass(jvmti, klass, method_name, method_sig);
        jni->DeleteGlobalRef(klass);
        if (!mid) {
            JsonBuf jb;
            json_start(&jb);
            json_add_string(&jb, "type", "error");
            char msg[512];
            snprintf(msg, sizeof(msg), "bp_set: method not found: %s.%s%s", class_sig, method_name, method_sig);
            json_add_string(&jb, "msg", msg);
            json_end(&jb);
            SendToClient(jb.buf);
            return;
        }

        // Set single breakpoint
        jvmtiError err = jvmti->SetBreakpoint(mid, location);
        if (err != JVMTI_ERROR_NONE) {
            JsonBuf jb;
            json_start(&jb);
            json_add_string(&jb, "type", "error");
            char msg[512];
            const char* hint = "";
            if (err == JVMTI_ERROR_DUPLICATE)           hint = " (JVMTI_ERROR_DUPLICATE — breakpoint already set)";
            else if (err == JVMTI_ERROR_INVALID_LOCATION)   hint = " (invalid location — method may be native/abstract)";
            else if (err == JVMTI_ERROR_NATIVE_METHOD)  hint = " (native method — cannot set breakpoint)";
            else if (err == JVMTI_ERROR_INVALID_METHODID) hint = " (invalid method ID)";
            snprintf(msg, sizeof(msg), "bp_set failed on %s.%s: JVMTI error %d%s",
                     class_sig, method_name, err, hint);
            json_add_string(&jb, "msg", msg);
            json_end(&jb);
            SendToClient(jb.buf);
            return;
        }

        jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_BREAKPOINT, nullptr);

        Breakpoint bp;
        bp.id = g_dbg.next_bp_id++;
        bp.method = mid;
        bp.location = location;
        strncpy(bp.class_sig, class_sig, sizeof(bp.class_sig) - 1);
        bp.class_sig[sizeof(bp.class_sig) - 1] = '\0';
        strncpy(bp.method_name, method_name, sizeof(bp.method_name) - 1);
        bp.method_name[sizeof(bp.method_name) - 1] = '\0';
        strncpy(bp.method_sig_str, method_sig, sizeof(bp.method_sig_str) - 1);
        bp.method_sig_str[sizeof(bp.method_sig_str) - 1] = '\0';
        g_dbg.breakpoints.push_back(bp);

        ALOGI("[DBG] Breakpoint #%d set: %s.%s%s @ %lld", bp.id, class_sig, method_name, method_sig, (long long)location);

        JsonBuf jb;
        json_start(&jb);
        json_add_string(&jb, "type", "bp_set_ok");
        json_add_int(&jb, "id", bp.id);
        json_add_string(&jb, "class", class_sig);
        json_add_string(&jb, "method", method_name);
        json_add_long(&jb, "location", (long long)location);
        json_end(&jb);
        SendToClient(jb.buf);
    } else {
        // No signature — set breakpoint on ALL overloads of this method name
        jint method_count = 0;
        jmethodID* methods = nullptr;
        if (jvmti->GetClassMethods(klass, &method_count, &methods) != JVMTI_ERROR_NONE) {
            jni->DeleteGlobalRef(klass);
            SendError("bp_set: GetClassMethods failed");
            return;
        }

        int set_count = 0;
        bool any_found = false;
        for (int i = 0; i < method_count; i++) {
            char* name = nullptr;
            char* sig = nullptr;
            if (jvmti->GetMethodName(methods[i], &name, &sig, nullptr) != JVMTI_ERROR_NONE)
                continue;
            bool match = (strcmp(name, method_name) == 0);
            if (match) {
                any_found = true;
                jvmtiError err = jvmti->SetBreakpoint(methods[i], location);
                if (err == JVMTI_ERROR_NONE) {
                    jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_BREAKPOINT, nullptr);

                    Breakpoint bp;
                    bp.id = g_dbg.next_bp_id++;
                    bp.method = methods[i];
                    bp.location = location;
                    strncpy(bp.class_sig, class_sig, sizeof(bp.class_sig) - 1);
                    bp.class_sig[sizeof(bp.class_sig) - 1] = '\0';
                    strncpy(bp.method_name, method_name, sizeof(bp.method_name) - 1);
                    bp.method_name[sizeof(bp.method_name) - 1] = '\0';
                    strncpy(bp.method_sig_str, sig ? sig : "", sizeof(bp.method_sig_str) - 1);
                    bp.method_sig_str[sizeof(bp.method_sig_str) - 1] = '\0';
                    g_dbg.breakpoints.push_back(bp);

                    ALOGI("[DBG] Breakpoint #%d set: %s.%s%s @ %lld", bp.id, class_sig, method_name, sig ? sig : "", (long long)location);

                    JsonBuf jb;
                    json_start(&jb);
                    json_add_string(&jb, "type", "bp_set_ok");
                    json_add_int(&jb, "id", bp.id);
                    json_add_string(&jb, "class", class_sig);
                    json_add_string(&jb, "method", method_name);
                    json_add_long(&jb, "location", (long long)location);
                    json_end(&jb);
                    SendToClient(jb.buf);
                    set_count++;
                } else if (err != JVMTI_ERROR_DUPLICATE) {
                    // Report non-duplicate errors but keep trying other overloads
                    char msg[512];
                    const char* hint = "";
                    if (err == JVMTI_ERROR_INVALID_LOCATION)   hint = " (native/abstract)";
                    else if (err == JVMTI_ERROR_NATIVE_METHOD)  hint = " (native)";
                    snprintf(msg, sizeof(msg), "bp_set skipped %s.%s%s: JVMTI error %d%s",
                             class_sig, method_name, sig ? sig : "", err, hint);
                    ALOGI("[DBG] %s", msg);
                }
                // Silently skip DUPLICATE — overload already has a bp
            }
            if (name) jvmti->Deallocate(reinterpret_cast<unsigned char*>(name));
            if (sig) jvmti->Deallocate(reinterpret_cast<unsigned char*>(sig));
        }
        jvmti->Deallocate(reinterpret_cast<unsigned char*>(methods));
        jni->DeleteGlobalRef(klass);

        if (!any_found) {
            char msg[512];
            snprintf(msg, sizeof(msg), "bp_set: method not found: %s.%s", class_sig, method_name);
            SendError(msg);
        } else if (set_count == 0) {
            char msg[512];
            snprintf(msg, sizeof(msg), "bp_set: all %s.%s overloads already have breakpoints or are native", class_sig, method_name);
            SendError(msg);
        }
    }
}

// bp_clear: remove a breakpoint by id
static void CmdBpClear(jvmtiEnv* jvmti, JNIEnv* jni, const char* json) {
    int bp_id = -1;
    if (!json_get_int(json, "id", &bp_id)) {
        JsonBuf jb;
        json_start(&jb);
        json_add_string(&jb, "type", "error");
        json_add_string(&jb, "msg", "missing 'id' param");
        json_end(&jb);
        SendToClient(jb.buf);
        return;
    }

    for (auto it = g_dbg.breakpoints.begin(); it != g_dbg.breakpoints.end(); ++it) {
        if (it->id == bp_id) {
            jvmti->ClearBreakpoint(it->method, it->location);
            ALOGI("[DBG] Breakpoint #%d cleared: %s.%s", bp_id, it->class_sig, it->method_name);
            g_dbg.breakpoints.erase(it);

            JsonBuf jb;
            json_start(&jb);
            json_add_string(&jb, "type", "bp_clear_ok");
            json_add_int(&jb, "id", bp_id);
            json_end(&jb);
            SendToClient(jb.buf);
            return;
        }
    }

    JsonBuf jb;
    json_start(&jb);
    json_add_string(&jb, "type", "error");
    json_add_string(&jb, "msg", "breakpoint not found");
    json_end(&jb);
    SendToClient(jb.buf);
}

// bp_list: list all breakpoints
static void CmdBpList(jvmtiEnv* jvmti, JNIEnv* jni, const char* json) {
    JsonArrayBuf ab;
    json_array_start(&ab);

    for (auto& bp : g_dbg.breakpoints) {
        JsonBuf obj;
        json_start(&obj);
        json_add_int(&obj, "id", bp.id);
        json_add_string(&obj, "class", bp.class_sig);
        json_add_string(&obj, "method", bp.method_name);
        json_add_string(&obj, "sig", bp.method_sig_str);
        json_add_long(&obj, "location", (long long)bp.location);
        json_end(&obj);
        obj.buf[obj.pos - 1] = '\0';
        obj.pos -= 1;
        json_array_add_object(&ab, obj.buf);
    }
    json_array_end(&ab);

    JsonBuf jb;
    json_start(&jb);
    json_add_string(&jb, "type", "bp_list_result");
    json_add_int(&jb, "count", (int)g_dbg.breakpoints.size());
    json_add_raw(&jb, "breakpoints", ab.buf);
    json_end(&jb);
    SendToClient(jb.buf);
}

// ---------------------------------------------------------------------------
// Milestone 2: FindBreakpointId
// ---------------------------------------------------------------------------

int FindBreakpointId(jmethodID method, jlocation location) {
    for (auto& bp : g_dbg.breakpoints) {
        if (bp.method == method && bp.location == location)
            return bp.id;
    }
    return -1;
}

// ---------------------------------------------------------------------------
// Deferred breakpoint activation (CLASS_PREPARE callback)
// ---------------------------------------------------------------------------

void HandleClassPrepare(jvmtiEnv* jvmti, JNIEnv* jni, jthread /*thread*/, jclass klass) {
    char* sig = nullptr;
    if (jvmti->GetClassSignature(klass, &sig, nullptr) != JVMTI_ERROR_NONE || !sig) return;

    // Collect matching entries under the lock, then release before calling JVMTI.
    // (Do NOT hold g_pending_mu while calling SetBreakpoint or SendToClient.)
    std::vector<PendingBreakpoint> to_activate;
    {
        pthread_mutex_lock(&g_pending_mu);
        auto it = g_pending_bps.begin();
        while (it != g_pending_bps.end()) {
            if (strcmp(sig, it->class_sig) == 0) {
                to_activate.push_back(*it);
                it = g_pending_bps.erase(it);
            } else {
                ++it;
            }
        }
        pthread_mutex_unlock(&g_pending_mu);
    }
    jvmti->Deallocate(reinterpret_cast<unsigned char*>(sig));

    for (const auto& pbp : to_activate) {
        jmethodID mid = FindMethodInClass(jvmti, klass,
                                          pbp.method_name,
                                          pbp.method_sig[0] ? pbp.method_sig : nullptr);
        if (!mid) {
            ALOGI("[DBG] BP#%d deferred: method not found after class load: %s.%s",
                  pbp.bp_id, pbp.class_sig, pbp.method_name);
            char msg[512];
            snprintf(msg, sizeof(msg), "deferred bp#%d: method not found: %s.%s",
                     pbp.bp_id, pbp.class_sig, pbp.method_name);
            SendError(msg);
            continue;
        }

        jvmtiError err = jvmti->SetBreakpoint(mid, 0);
        if (err != JVMTI_ERROR_NONE) {
            ALOGI("[DBG] BP#%d deferred: SetBreakpoint failed: %d", pbp.bp_id, err);
            char msg[512];
            snprintf(msg, sizeof(msg), "deferred bp#%d: SetBreakpoint failed (err=%d): %s.%s",
                     pbp.bp_id, err, pbp.class_sig, pbp.method_name);
            SendError(msg);
            continue;
        }

        jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_BREAKPOINT, nullptr);

        // Register in the active breakpoints table
        Breakpoint bp;
        bp.id = pbp.bp_id;
        bp.method = mid;
        bp.location = 0;
        strncpy(bp.class_sig, pbp.class_sig, sizeof(bp.class_sig) - 1);
        bp.class_sig[sizeof(bp.class_sig) - 1] = '\0';
        strncpy(bp.method_name, pbp.method_name, sizeof(bp.method_name) - 1);
        bp.method_name[sizeof(bp.method_name) - 1] = '\0';
        strncpy(bp.method_sig_str, pbp.method_sig, sizeof(bp.method_sig_str) - 1);
        bp.method_sig_str[sizeof(bp.method_sig_str) - 1] = '\0';
        g_dbg.breakpoints.push_back(bp);

        ALOGI("[DBG] BP#%d activated: %s.%s @0", pbp.bp_id, pbp.class_sig, pbp.method_name);

        // Notify server — same message as a normal bp_set_ok
        JsonBuf jb;
        json_start(&jb);
        json_add_string(&jb, "type", "bp_set_ok");
        json_add_int(&jb, "id", pbp.bp_id);
        json_add_string(&jb, "class", pbp.class_sig);
        json_add_string(&jb, "method", pbp.method_name);
        json_add_long(&jb, "location", 0LL);
        json_end(&jb);
        SendToClient(jb.buf);
    }
}

// ---------------------------------------------------------------------------
// Milestone 3: Suspended-thread commands (run inside DebuggerCommandLoop)
// ---------------------------------------------------------------------------

// Forward declaration — defined later in Milestone 4 (global commands)
static void CmdRedefineClass(jvmtiEnv* jvmti, JNIEnv* jni, const char* json);

// Write up to max_bytes of hex from a jbyteArray into out buffer.
// Returns number of chars written (not counting NUL).
static int FormatByteArrayShortHex(JNIEnv* jni, jbyteArray arr, char* out, size_t out_len, int max_bytes = 8) {
    if (!arr || out_len < 3) return 0;
    jint len = jni->GetArrayLength(arr);
    int show = len < max_bytes ? len : max_bytes;
    jbyte* bytes = jni->GetByteArrayElements(arr, nullptr);
    if (!bytes) return 0;
    int pos = 0;
    for (int i = 0; i < show && pos + 2 < (int)out_len; i++) {
        pos += snprintf(out + pos, out_len - pos, "%02x", (unsigned char)bytes[i]);
    }
    if (len > max_bytes && pos + 3 < (int)out_len) {
        pos += snprintf(out + pos, out_len - pos, "..");
    }
    jni->ReleaseByteArrayElements(arr, bytes, JNI_ABORT);
    return pos;
}

// Format an object value for display (String, array, or class name)
// detailed=true: crypto-aware formatting; detailed=false: fast path (toString only)
void FormatObjectValue(JNIEnv* jni, jobject obj, char* out, size_t out_len, bool detailed) {
    if (!obj) {
        snprintf(out, out_len, "null");
        return;
    }

    jclass str_class = jni->FindClass("java/lang/String");
    if (str_class && jni->IsInstanceOf(obj, str_class)) {
        const char* s = jni->GetStringUTFChars((jstring)obj, nullptr);
        if (s) {
            snprintf(out, out_len, "\"%.*s\"", (int)(out_len - 3), s);
            jni->ReleaseStringUTFChars((jstring)obj, s);
        } else {
            snprintf(out, out_len, "<string?>");
        }
        jni->DeleteLocalRef(str_class);
        // Sanitize control characters before returning
        for (size_t i = 0; out[i]; i++) {
            if ((unsigned char)out[i] < 0x20) out[i] = ' ';
        }
        return;
    }
    if (str_class) jni->DeleteLocalRef(str_class);

    // Check for arrays
    jclass obj_class = jni->GetObjectClass(obj);
    jclass cls_class = jni->FindClass("java/lang/Class");
    jmethodID isArray = jni->GetMethodID(cls_class, "isArray", "()Z");
    jboolean is_arr = jni->CallBooleanMethod(obj_class, isArray);
    if (jni->ExceptionCheck()) { jni->ExceptionClear(); is_arr = false; }

    if (is_arr) {
        // Get array component type to decide how to format
        jmethodID getCompType = jni->GetMethodID(cls_class, "getComponentType", "()Ljava/lang/Class;");
        jclass comp_class = getCompType ? (jclass)jni->CallObjectMethod(obj_class, getCompType) : nullptr;
        if (jni->ExceptionCheck()) { jni->ExceptionClear(); comp_class = nullptr; }

        jclass str_cls = jni->FindClass("java/lang/String");
        jint arr_len = jni->GetArrayLength((jarray)obj);
        bool is_string_arr = comp_class && str_cls && jni->IsAssignableFrom(comp_class, str_cls);
        bool is_object_arr = false;
        if (!is_string_arr && comp_class) {
            // Check if component type is an object (not primitive) — Object[] arrays
            jmethodID isPrim = jni->GetMethodID(cls_class, "isPrimitive", "()Z");
            if (isPrim) {
                jboolean prim = jni->CallBooleanMethod(comp_class, isPrim);
                if (jni->ExceptionCheck()) { jni->ExceptionClear(); prim = true; }
                is_object_arr = !prim;
            }
        }

        if ((is_string_arr || is_object_arr) && arr_len > 0) {
            // Expand elements: show up to 4 values
            int max_show = arr_len < 4 ? arr_len : 4;
            int pos = 0;
            pos += snprintf(out + pos, out_len - pos, "[");
            for (int i = 0; i < max_show && pos < (int)out_len - 8; i++) {
                if (i > 0) pos += snprintf(out + pos, out_len - pos, ", ");
                jobject elem = jni->GetObjectArrayElement((jobjectArray)obj, i);
                if (jni->ExceptionCheck()) { jni->ExceptionClear(); elem = nullptr; }
                if (!elem) {
                    pos += snprintf(out + pos, out_len - pos, "null");
                } else if (jni->IsInstanceOf(elem, str_cls)) {
                    const char* sv = jni->GetStringUTFChars((jstring)elem, nullptr);
                    if (sv) {
                        // Truncate long strings
                        pos += snprintf(out + pos, out_len - pos, "\"%.60s%s\"",
                                        sv, strlen(sv) > 60 ? "..." : "");
                        jni->ReleaseStringUTFChars((jstring)elem, sv);
                    } else {
                        pos += snprintf(out + pos, out_len - pos, "\"?\"");
                    }
                } else {
                    // Non-string object: show class@...
                    jclass ec = jni->GetObjectClass(elem);
                    jmethodID gn = jni->GetMethodID(cls_class, "getName", "()Ljava/lang/String;");
                    jstring en = gn ? (jstring)jni->CallObjectMethod(ec, gn) : nullptr;
                    if (!jni->ExceptionCheck() && en) {
                        const char* es = jni->GetStringUTFChars(en, nullptr);
                        pos += snprintf(out + pos, out_len - pos, "%s@...", es ? es : "?");
                        if (es) jni->ReleaseStringUTFChars(en, es);
                        jni->DeleteLocalRef(en);
                    } else {
                        if (jni->ExceptionCheck()) jni->ExceptionClear();
                        pos += snprintf(out + pos, out_len - pos, "<obj>");
                    }
                    jni->DeleteLocalRef(ec);
                }
                if (elem) jni->DeleteLocalRef(elem);
            }
            if (arr_len > max_show) {
                pos += snprintf(out + pos, out_len - pos, ", ...+%d", arr_len - max_show);
            }
            snprintf(out + pos, out_len - pos, "]");
        } else {
            // Primitive array or empty: show type[len] + hex for byte[]
            jmethodID getName = jni->GetMethodID(cls_class, "getName", "()Ljava/lang/String;");
            jstring name = (jstring)jni->CallObjectMethod(obj_class, getName);
            const char* type_name = nullptr;
            if (!jni->ExceptionCheck() && name) {
                type_name = jni->GetStringUTFChars(name, nullptr);
            } else {
                if (jni->ExceptionCheck()) jni->ExceptionClear();
            }
            // Check if it's byte[] — dump hex content
            if (type_name && strcmp(type_name, "[B") == 0 && arr_len > 0) {
                char hex[130] = {};
                FormatByteArrayShortHex(jni, (jbyteArray)obj, hex, sizeof(hex), 64);
                snprintf(out, out_len, "byte[%d](%s)", arr_len, hex);
            } else {
                snprintf(out, out_len, "%s[%d]", type_name ? type_name : "<array>", arr_len);
            }
            if (type_name && name) jni->ReleaseStringUTFChars(name, type_name);
            if (name) jni->DeleteLocalRef(name);
        }
        if (str_cls) jni->DeleteLocalRef(str_cls);
        if (comp_class) jni->DeleteLocalRef(comp_class);
    } else if (detailed) {
        // --- Crypto-aware formatting before generic toString() ---
        bool handled = false;

        // SecretKeySpec → "SecretKeySpec(AES,16b,00112233...full hex...)"
        jclass sks_class = jni->FindClass("javax/crypto/spec/SecretKeySpec");
        if (sks_class && jni->IsInstanceOf(obj, sks_class)) {
            jmethodID getAlg = jni->GetMethodID(sks_class, "getAlgorithm", "()Ljava/lang/String;");
            jmethodID getEnc = jni->GetMethodID(sks_class, "getEncoded", "()[B");
            const char* alg_str = "?";
            jstring alg = getAlg ? (jstring)jni->CallObjectMethod(obj, getAlg) : nullptr;
            if (jni->ExceptionCheck()) { jni->ExceptionClear(); alg = nullptr; }
            if (alg) alg_str = jni->GetStringUTFChars(alg, nullptr);
            jbyteArray enc = getEnc ? (jbyteArray)jni->CallObjectMethod(obj, getEnc) : nullptr;
            if (jni->ExceptionCheck()) { jni->ExceptionClear(); enc = nullptr; }
            int enc_len = enc ? jni->GetArrayLength(enc) : 0;
            char hex[130] = {};
            if (enc) FormatByteArrayShortHex(jni, enc, hex, sizeof(hex), 64);
            snprintf(out, out_len, "SecretKeySpec(%s,%db,%s)", alg_str, enc_len, hex);
            if (alg && alg_str) jni->ReleaseStringUTFChars(alg, alg_str);
            if (alg) jni->DeleteLocalRef(alg);
            if (enc) jni->DeleteLocalRef(enc);
            handled = true;
        }
        if (sks_class) jni->DeleteLocalRef(sks_class);

        // IvParameterSpec → "IvParameterSpec(16b,00112233...full hex...)"
        if (!handled) {
            jclass ivps_class = jni->FindClass("javax/crypto/spec/IvParameterSpec");
            if (ivps_class && jni->IsInstanceOf(obj, ivps_class)) {
                jmethodID getIV = jni->GetMethodID(ivps_class, "getIV", "()[B");
                jbyteArray iv = getIV ? (jbyteArray)jni->CallObjectMethod(obj, getIV) : nullptr;
                if (jni->ExceptionCheck()) { jni->ExceptionClear(); iv = nullptr; }
                int iv_len = iv ? jni->GetArrayLength(iv) : 0;
                char hex[130] = {};
                if (iv) FormatByteArrayShortHex(jni, iv, hex, sizeof(hex), 64);
                snprintf(out, out_len, "IvParameterSpec(%db,%s)", iv_len, hex);
                if (iv) jni->DeleteLocalRef(iv);
                handled = true;
            }
            if (ivps_class) jni->DeleteLocalRef(ivps_class);
        }

        // Cipher → "Cipher(AES/CBC/PKCS5Padding)"
        if (!handled) {
            jclass cipher_class = jni->FindClass("javax/crypto/Cipher");
            if (cipher_class && jni->IsInstanceOf(obj, cipher_class)) {
                jmethodID getAlg = jni->GetMethodID(cipher_class, "getAlgorithm", "()Ljava/lang/String;");
                jstring alg = getAlg ? (jstring)jni->CallObjectMethod(obj, getAlg) : nullptr;
                if (jni->ExceptionCheck()) { jni->ExceptionClear(); alg = nullptr; }
                if (alg) {
                    const char* s = jni->GetStringUTFChars(alg, nullptr);
                    snprintf(out, out_len, "Cipher(%s)", s ? s : "?");
                    if (s) jni->ReleaseStringUTFChars(alg, s);
                    jni->DeleteLocalRef(alg);
                } else {
                    snprintf(out, out_len, "Cipher(?)");
                }
                handled = true;
            }
            if (cipher_class) jni->DeleteLocalRef(cipher_class);
        }

        // SecureRandom → just "SecureRandom"
        if (!handled) {
            jclass sr_class = jni->FindClass("java/security/SecureRandom");
            if (sr_class && jni->IsInstanceOf(obj, sr_class)) {
                snprintf(out, out_len, "SecureRandom");
                handled = true;
            }
            if (sr_class) jni->DeleteLocalRef(sr_class);
        }

        // Key (generic interface) → "Key(AES,16b)"
        if (!handled) {
            jclass key_class = jni->FindClass("java/security/Key");
            if (key_class && jni->IsInstanceOf(obj, key_class)) {
                jmethodID getAlg = jni->GetMethodID(key_class, "getAlgorithm", "()Ljava/lang/String;");
                jmethodID getEnc = jni->GetMethodID(key_class, "getEncoded", "()[B");
                const char* alg_str = "?";
                jstring alg = getAlg ? (jstring)jni->CallObjectMethod(obj, getAlg) : nullptr;
                if (jni->ExceptionCheck()) { jni->ExceptionClear(); alg = nullptr; }
                if (alg) alg_str = jni->GetStringUTFChars(alg, nullptr);
                jbyteArray enc = getEnc ? (jbyteArray)jni->CallObjectMethod(obj, getEnc) : nullptr;
                if (jni->ExceptionCheck()) { jni->ExceptionClear(); enc = nullptr; }
                int enc_len = enc ? jni->GetArrayLength(enc) : 0;
                snprintf(out, out_len, "Key(%s,%db)", alg_str, enc_len);
                if (alg && alg_str) jni->ReleaseStringUTFChars(alg, alg_str);
                if (alg) jni->DeleteLocalRef(alg);
                if (enc) jni->DeleteLocalRef(enc);
                handled = true;
            }
            if (key_class) jni->DeleteLocalRef(key_class);
        }

        if (!handled) {
            // Call toString() for a readable representation
            jmethodID toString = jni->GetMethodID(obj_class, "toString", "()Ljava/lang/String;");
            jstring ts_result = toString ? (jstring)jni->CallObjectMethod(obj, toString) : nullptr;
            if (jni->ExceptionCheck()) { jni->ExceptionClear(); ts_result = nullptr; }
            if (ts_result) {
                const char* s = jni->GetStringUTFChars(ts_result, nullptr);
                if (s) {
                    size_t max_chars = out_len > 4 ? out_len - 4 : out_len;
                    snprintf(out, out_len, "%.*s%s", (int)max_chars, s, strlen(s) > max_chars ? "..." : "");
                    jni->ReleaseStringUTFChars(ts_result, s);
                } else {
                    snprintf(out, out_len, "<object>");
                }
                jni->DeleteLocalRef(ts_result);
            } else {
                // toString() failed — fall back to class name
                jmethodID getName = jni->GetMethodID(cls_class, "getName", "()Ljava/lang/String;");
                jstring name = getName ? (jstring)jni->CallObjectMethod(obj_class, getName) : nullptr;
                if (!jni->ExceptionCheck() && name) {
                    const char* s = jni->GetStringUTFChars(name, nullptr);
                    snprintf(out, out_len, "%s@...", s ? s : "?");
                    if (s) jni->ReleaseStringUTFChars(name, s);
                    jni->DeleteLocalRef(name);
                } else {
                    if (jni->ExceptionCheck()) jni->ExceptionClear();
                    snprintf(out, out_len, "<object>");
                }
            }
        } // !handled
    } else {
        // Fast path (detailed=false): just toString()
        jmethodID toString = jni->GetMethodID(obj_class, "toString", "()Ljava/lang/String;");
        jstring ts_result = toString ? (jstring)jni->CallObjectMethod(obj, toString) : nullptr;
        if (jni->ExceptionCheck()) { jni->ExceptionClear(); ts_result = nullptr; }
        if (ts_result) {
            const char* s = jni->GetStringUTFChars(ts_result, nullptr);
            if (s) {
                size_t max_chars = out_len > 4 ? out_len - 4 : out_len;
                snprintf(out, out_len, "%.*s%s", (int)max_chars, s, strlen(s) > max_chars ? "..." : "");
                jni->ReleaseStringUTFChars(ts_result, s);
            } else {
                snprintf(out, out_len, "<object>");
            }
            jni->DeleteLocalRef(ts_result);
        } else {
            jmethodID getName = jni->GetMethodID(cls_class, "getName", "()Ljava/lang/String;");
            jstring name = getName ? (jstring)jni->CallObjectMethod(obj_class, getName) : nullptr;
            if (!jni->ExceptionCheck() && name) {
                const char* s = jni->GetStringUTFChars(name, nullptr);
                snprintf(out, out_len, "%s@...", s ? s : "?");
                if (s) jni->ReleaseStringUTFChars(name, s);
                jni->DeleteLocalRef(name);
            } else {
                if (jni->ExceptionCheck()) jni->ExceptionClear();
                snprintf(out, out_len, "<object>");
            }
        }
    }

    jni->DeleteLocalRef(cls_class);
    jni->DeleteLocalRef(obj_class);

    // Sanitize control characters (newlines, tabs, etc.) that break JSON
    for (size_t i = 0; out[i]; i++) {
        if ((unsigned char)out[i] < 0x20) out[i] = ' ';
    }
}

// locals: get local variables at frame 0
static void CmdLocals(jvmtiEnv* jvmti, JNIEnv* jni, jthread thread,
                      jmethodID method, jlocation location) {
    if (!g_dbg.cap_local_vars) {
        SendError("Local variable access not available on this device/Android version");
        return;
    }
    jint var_count = 0;
    jvmtiLocalVariableEntry* var_table = nullptr;
    bool have_table = (jvmti->GetLocalVariableTable(method, &var_count, &var_table)
                       == JVMTI_ERROR_NONE);

    // Get max_locals for fallback
    jint max_locals = 0;
    jvmti->GetMaxLocals(method, &max_locals);

    JsonArrayBuf ab;
    json_array_start(&ab);

    if (have_table && var_table) {
        // Use debug info
        // Track which slots have a live (non-stale) variable table entry so we
        // can emit uncovered slots below (temp registers like const/4 v1 targets).
        std::vector<bool> slot_covered(max_locals, false);

        for (int i = 0; i < var_count; i++) {
            jvmtiLocalVariableEntry& v = var_table[i];
            // Check if variable is live at current location
            bool stale = (location < v.start_location ||
                          location >= v.start_location + v.length);
            if (!stale && v.slot >= 0 && v.slot < max_locals)
                slot_covered[v.slot] = true;

            JsonBuf obj;
            json_start(&obj);
            json_add_int(&obj, "slot", v.slot);
            json_add_string(&obj, "name", v.name ? v.name : "?");
            json_add_string(&obj, "type", v.signature ? v.signature : "?");
            if (stale) json_add_bool(&obj, "stale", true);

            char value_str[512];
            value_str[0] = '\0';

            if (!stale && v.signature) {
                char sig0 = v.signature[0];
                jvmtiError err;
                if (sig0 == 'I' || sig0 == 'B' || sig0 == 'S' || sig0 == 'Z' || sig0 == 'C') {
                    jint val = 0;
                    err = jvmti->GetLocalInt(thread, 0, v.slot, &val);
                    if (err == JVMTI_ERROR_NONE) {
                        if (sig0 == 'Z')
                            snprintf(value_str, sizeof(value_str), "%s", val ? "true" : "false");
                        else if (sig0 == 'C')
                            snprintf(value_str, sizeof(value_str), "'%c' (%d)", (char)val, val);
                        else
                            snprintf(value_str, sizeof(value_str), "%d", val);
                    }
                } else if (sig0 == 'J') {
                    jlong val = 0;
                    err = jvmti->GetLocalLong(thread, 0, v.slot, &val);
                    if (err == JVMTI_ERROR_NONE)
                        snprintf(value_str, sizeof(value_str), "%lld", (long long)val);
                } else if (sig0 == 'F') {
                    jfloat val = 0;
                    err = jvmti->GetLocalFloat(thread, 0, v.slot, &val);
                    if (err == JVMTI_ERROR_NONE)
                        snprintf(value_str, sizeof(value_str), "%f", val);
                } else if (sig0 == 'D') {
                    jdouble val = 0;
                    err = jvmti->GetLocalDouble(thread, 0, v.slot, &val);
                    if (err == JVMTI_ERROR_NONE)
                        snprintf(value_str, sizeof(value_str), "%f", val);
                } else if (sig0 == 'L' || sig0 == '[') {
                    jobject val = nullptr;
                    err = jvmti->GetLocalObject(thread, 0, v.slot, &val);
                    if (err == JVMTI_ERROR_NONE) {
                        FormatObjectValue(jni, val, value_str, sizeof(value_str));
                        if (val) jni->DeleteLocalRef(val);
                    }
                }
            }

            json_add_string(&obj, "value", value_str[0] ? value_str : "<unavailable>");
            json_end(&obj);
            obj.buf[obj.pos - 1] = '\0';
            obj.pos -= 1;
            json_array_add_object(&ab, obj.buf);

            // Free JVMTI-allocated strings
            if (v.name) jvmti->Deallocate(reinterpret_cast<unsigned char*>(v.name));
            if (v.signature) jvmti->Deallocate(reinterpret_cast<unsigned char*>(v.signature));
            if (v.generic_signature) jvmti->Deallocate(reinterpret_cast<unsigned char*>(v.generic_signature));
        }
        jvmti->Deallocate(reinterpret_cast<unsigned char*>(var_table));

        // Emit uncovered slots (temp registers with no debug-info entry at this PC)
        for (int slot = 0; slot < max_locals; slot++) {
            if (slot_covered[slot]) continue;
            char slot_name[16];
            snprintf(slot_name, sizeof(slot_name), "v%d", slot);
            char value_str[64] = "";
            jint ival = 0;
            if (jvmti->GetLocalInt(thread, 0, slot, &ival) == JVMTI_ERROR_NONE)
                snprintf(value_str, sizeof(value_str), "%d (0x%x)", ival, (unsigned)ival);
            JsonBuf obj;
            json_start(&obj);
            json_add_int(&obj, "slot", slot);
            json_add_string(&obj, "name", slot_name);
            json_add_string(&obj, "type", "?");
            json_add_string(&obj, "value", value_str[0] ? value_str : "<unavailable>");
            json_end(&obj);
            obj.buf[obj.pos - 1] = '\0';
            obj.pos -= 1;
            json_array_add_object(&ab, obj.buf);
        }
    } else {
        // Fallback: no debug info, dump raw register values
        for (int slot = 0; slot < max_locals; slot++) {
            JsonBuf obj;
            json_start(&obj);
            json_add_int(&obj, "slot", slot);

            char slot_name[16];
            snprintf(slot_name, sizeof(slot_name), "v%d", slot);
            json_add_string(&obj, "name", slot_name);
            json_add_string(&obj, "type", "?");

            // No type info — try int first (most slots in no-debug-info methods are
            // primitive), then object. Both ART getters log on type mismatch so we
            // accept one spurious logcat line per reference slot in this fallback.
            char value_str[512] = "";
            jint ival = 0;
            if (jvmti->GetLocalInt(thread, 0, slot, &ival) == JVMTI_ERROR_NONE) {
                snprintf(value_str, sizeof(value_str), "%d (0x%x)", ival, (unsigned)ival);
            } else {
                jobject oval = nullptr;
                if (jvmti->GetLocalObject(thread, 0, slot, &oval) == JVMTI_ERROR_NONE) {
                    FormatObjectValue(jni, oval, value_str, sizeof(value_str));
                    if (oval) jni->DeleteLocalRef(oval);
                }
            }

            json_add_string(&obj, "value", value_str[0] ? value_str : "<unavailable>");
            json_end(&obj);
            obj.buf[obj.pos - 1] = '\0';
            obj.pos -= 1;
            json_array_add_object(&ab, obj.buf);
        }
    }

    json_array_end(&ab);

    JsonBuf jb;
    json_start(&jb);
    json_add_string(&jb, "type", "locals_result");
    json_add_raw(&jb, "vars", ab.buf);
    json_end(&jb);
    SendToClient(jb.buf);
}

// regs: dump ALL register slot values (raw int for each slot)
static void CmdRegs(jvmtiEnv* jvmti, JNIEnv* jni, jthread thread,
                    jmethodID method) {
    if (!g_dbg.cap_local_vars) {
        SendError("Register access not available on this device/Android version");
        return;
    }
    jint max_locals = 0;
    jvmti->GetMaxLocals(method, &max_locals);

    // Build a slot type map from the variable table so we call the right
    // getter without triggering ART's LOG(ERROR) on type mismatch.
    // Both GetLocalObject-on-primitive and GetLocalInt-on-reference log errors.
    // 0 = unknown/int, 1 = reference, 2 = long/double
    // Only apply type hints for variables that are live at the current BCI —
    // slots are reused by the compiler, so a slot that holds a reference later
    // in the method may hold an int right now.
    std::vector<int> slot_kind(max_locals, 0);
    jlocation cur_location = 0;
    {
        jmethodID cur_method = nullptr;
        jvmti->GetFrameLocation(thread, 0, &cur_method, &cur_location);
    }
    jint var_count = 0;
    jvmtiLocalVariableEntry* var_table = nullptr;
    if (jvmti->GetLocalVariableTable(method, &var_count, &var_table) == JVMTI_ERROR_NONE
            && var_table) {
        for (int i = 0; i < var_count; i++) {
            int s = var_table[i].slot;
            if (s < 0 || s >= max_locals) continue;
            if (!var_table[i].signature) continue;
            // Only use the type hint if this variable is live at the current BCI
            if (cur_location < var_table[i].start_location ||
                cur_location >= var_table[i].start_location + var_table[i].length) {
                if (var_table[i].name) jvmti->Deallocate(reinterpret_cast<unsigned char*>(var_table[i].name));
                if (var_table[i].signature) jvmti->Deallocate(reinterpret_cast<unsigned char*>(var_table[i].signature));
                if (var_table[i].generic_signature) jvmti->Deallocate(reinterpret_cast<unsigned char*>(var_table[i].generic_signature));
                continue;
            }
            char sig0 = var_table[i].signature[0];
            if (sig0 == 'L' || sig0 == '[')
                slot_kind[s] = 1;
            else if (sig0 == 'J' || sig0 == 'D')
                slot_kind[s] = 2;
            if (var_table[i].name) jvmti->Deallocate(reinterpret_cast<unsigned char*>(var_table[i].name));
            if (var_table[i].signature) jvmti->Deallocate(reinterpret_cast<unsigned char*>(var_table[i].signature));
            if (var_table[i].generic_signature) jvmti->Deallocate(reinterpret_cast<unsigned char*>(var_table[i].generic_signature));
        }
        jvmti->Deallocate(reinterpret_cast<unsigned char*>(var_table));
    }

    JsonArrayBuf ab;
    json_array_start(&ab);

    for (int slot = 0; slot < max_locals; slot++) {
        if (slot_kind[slot] == 1) {
            // Known reference slot
            jobject oval = nullptr;
            if (jvmti->GetLocalObject(thread, 0, slot, &oval) == JVMTI_ERROR_NONE) {
                JsonBuf obj;
                json_start(&obj);
                json_add_int(&obj, "slot", slot);
                json_add_long(&obj, "value", oval != nullptr ? 1 : 0);
                json_end(&obj);
                obj.buf[obj.pos - 1] = '\0';
                obj.pos -= 1;
                json_array_add_object(&ab, obj.buf);
                if (oval) jni->DeleteLocalRef(oval);
            }
        } else if (slot_kind[slot] == 2) {
            // Known long/double slot
            jlong lval = 0;
            if (jvmti->GetLocalLong(thread, 0, slot, &lval) == JVMTI_ERROR_NONE) {
                JsonBuf obj;
                json_start(&obj);
                json_add_int(&obj, "slot", slot);
                json_add_long(&obj, "value", (long long)lval);
                json_end(&obj);
                obj.buf[obj.pos - 1] = '\0';
                obj.pos -= 1;
                json_array_add_object(&ab, obj.buf);
            }
        } else {
            // Unknown or known-int slot. Probe order: int → object → long.
            // References are more common than longs, so skipping long first
            // means at most one spurious log per unknown reference slot (from
            // the int attempt), vs two logs with int → long → object.
            jint ival = 0;
            jvmtiError err = jvmti->GetLocalInt(thread, 0, slot, &ival);
            if (err == JVMTI_ERROR_NONE) {
                JsonBuf obj;
                json_start(&obj);
                json_add_int(&obj, "slot", slot);
                json_add_int(&obj, "value", ival);
                json_end(&obj);
                obj.buf[obj.pos - 1] = '\0';
                obj.pos -= 1;
                json_array_add_object(&ab, obj.buf);
            } else {
                jobject oval = nullptr;
                err = jvmti->GetLocalObject(thread, 0, slot, &oval);
                if (err == JVMTI_ERROR_NONE) {
                    JsonBuf obj;
                    json_start(&obj);
                    json_add_int(&obj, "slot", slot);
                    json_add_long(&obj, "value", oval != nullptr ? 1 : 0);
                    json_end(&obj);
                    obj.buf[obj.pos - 1] = '\0';
                    obj.pos -= 1;
                    json_array_add_object(&ab, obj.buf);
                    if (oval) jni->DeleteLocalRef(oval);
                } else {
                    jlong lval = 0;
                    if (jvmti->GetLocalLong(thread, 0, slot, &lval) == JVMTI_ERROR_NONE) {
                        JsonBuf obj;
                        json_start(&obj);
                        json_add_int(&obj, "slot", slot);
                        json_add_long(&obj, "value", (long long)lval);
                        json_end(&obj);
                        obj.buf[obj.pos - 1] = '\0';
                        obj.pos -= 1;
                        json_array_add_object(&ab, obj.buf);
                    }
                }
            }
        }
    }

    json_array_end(&ab);

    JsonBuf jb;
    json_start(&jb);
    json_add_string(&jb, "type", "regs_result");
    json_add_raw(&jb, "regs", ab.buf);
    json_end(&jb);
    SendToClient(jb.buf);
}

// stack: get current call stack
static void CmdStack(jvmtiEnv* jvmti, JNIEnv* jni, jthread thread) {
    jvmtiFrameInfo frames[64];
    jint frame_count = 0;
    if (jvmti->GetStackTrace(thread, 0, 64, frames, &frame_count) != JVMTI_ERROR_NONE) {
        JsonBuf jb;
        json_start(&jb);
        json_add_string(&jb, "type", "error");
        json_add_string(&jb, "msg", "GetStackTrace failed");
        json_end(&jb);
        SendToClient(jb.buf);
        return;
    }

    JsonArrayBuf ab;
    json_array_start(&ab);

    for (int i = 0; i < frame_count; i++) {
        char* class_sig = nullptr;
        char* name = nullptr;
        char* sig = nullptr;
        GetMethodInfo(jvmti, frames[i].method, &class_sig, &name, &sig);

        int line = LocationToLine(jvmti, frames[i].method, frames[i].location);

        JsonBuf obj;
        json_start(&obj);
        json_add_int(&obj, "depth", i);
        json_add_string(&obj, "class", class_sig ? class_sig : "?");
        json_add_string(&obj, "method", name ? name : "?");
        json_add_string(&obj, "sig", sig ? sig : "?");
        json_add_long(&obj, "location", (long long)frames[i].location);
        json_add_int(&obj, "line", line);
        json_end(&obj);
        obj.buf[obj.pos - 1] = '\0';
        obj.pos -= 1;
        json_array_add_object(&ab, obj.buf);

        FreeMethodInfo(jvmti, class_sig, name, sig);
    }
    json_array_end(&ab);

    JsonBuf jb;
    json_start(&jb);
    json_add_string(&jb, "type", "stack_result");
    json_add_int(&jb, "count", frame_count);
    json_add_raw(&jb, "frames", ab.buf);
    json_end(&jb);
    SendToClient(jb.buf);
}

// inspect: inspect an object at a given local variable slot
static void CmdInspect(jvmtiEnv* jvmti, JNIEnv* jni, jthread thread,
                       const char* json) {
    int slot = -1;
    if (!json_get_int(json, "slot", &slot)) {
        JsonBuf jb;
        json_start(&jb);
        json_add_string(&jb, "type", "error");
        json_add_string(&jb, "msg", "missing 'slot' param");
        json_end(&jb);
        SendToClient(jb.buf);
        return;
    }

    int depth = 0;
    json_get_int(json, "depth", &depth);

    jobject obj = nullptr;
    jvmtiError err = jvmti->GetLocalObject(thread, depth, slot, &obj);
    if (err != JVMTI_ERROR_NONE || !obj) {
        JsonBuf jb;
        json_start(&jb);
        json_add_string(&jb, "type", "error");
        char msg[128];
        snprintf(msg, sizeof(msg), "GetLocalObject failed (err=%d, slot=%d)", err, slot);
        json_add_string(&jb, "msg", msg);
        json_end(&jb);
        SendToClient(jb.buf);
        return;
    }

    jclass obj_class = jni->GetObjectClass(obj);
    char* class_sig = nullptr;
    jvmti->GetClassSignature(obj_class, &class_sig, nullptr);

    // Special case: object arrays ([L..., [[...) — enumerate elements
    if (class_sig && class_sig[0] == '[' && class_sig[1] != 'B'
        && (class_sig[1] == 'L' || class_sig[1] == '[')) {
        jint arr_len = jni->GetArrayLength((jarray)obj);
        int show = arr_len < 200 ? arr_len : 200;

        JsonArrayBuf ab;
        json_array_start(&ab);

        // Length field first
        {
            JsonBuf lobj;
            json_start(&lobj);
            json_add_string(&lobj, "name", "length");
            json_add_string(&lobj, "type", "I");
            char ls[16]; snprintf(ls, sizeof(ls), "%d", arr_len);
            json_add_string(&lobj, "value", ls);
            json_end(&lobj);
            lobj.buf[lobj.pos - 1] = '\0'; lobj.pos -= 1;
            json_array_add_object(&ab, lobj.buf);
        }

        for (int i = 0; i < show; i++) {
            jobject elem = jni->GetObjectArrayElement((jobjectArray)obj, i);
            char val[512] = "";
            FormatObjectValue(jni, elem, val, sizeof(val));
            if (elem) jni->DeleteLocalRef(elem);

            JsonBuf fobj;
            json_start(&fobj);
            char idx_name[16]; snprintf(idx_name, sizeof(idx_name), "[%d]", i);
            json_add_string(&fobj, "name", idx_name);
            json_add_string(&fobj, "type", class_sig + 1); // element type
            json_add_string(&fobj, "value", val[0] ? val : "null");
            json_end(&fobj);
            fobj.buf[fobj.pos - 1] = '\0'; fobj.pos -= 1;
            json_array_add_object(&ab, fobj.buf);
        }
        json_array_end(&ab);

        JsonBuf jb;
        json_start(&jb);
        json_add_string(&jb, "type", "inspect_result");
        json_add_string(&jb, "class", class_sig);
        json_add_int(&jb, "slot", slot);
        json_add_raw(&jb, "fields", ab.buf);
        json_end(&jb);
        SendToClient(jb.buf);

        jvmti->Deallocate(reinterpret_cast<unsigned char*>(class_sig));
        jni->DeleteLocalRef(obj_class);
        jni->DeleteLocalRef(obj);
        return;
    }

    // Special case: byte[] — dump hex content as a single "data" field
    if (class_sig && strcmp(class_sig, "[B") == 0) {
        jint arr_len = jni->GetArrayLength((jarray)obj);
        char hex[130] = {};
        FormatByteArrayShortHex(jni, (jbyteArray)obj, hex, sizeof(hex), 64);

        JsonArrayBuf ab;
        json_array_start(&ab);
        JsonBuf fobj;
        json_start(&fobj);
        json_add_string(&fobj, "name", "data");
        json_add_string(&fobj, "type", "B");
        json_add_string(&fobj, "value", hex);
        json_end(&fobj);
        fobj.buf[fobj.pos - 1] = '\0';
        fobj.pos -= 1;
        json_array_add_object(&ab, fobj.buf);
        // Also add length field
        JsonBuf lobj;
        json_start(&lobj);
        json_add_string(&lobj, "name", "length");
        json_add_string(&lobj, "type", "I");
        char len_str[16];
        snprintf(len_str, sizeof(len_str), "%d", arr_len);
        json_add_string(&lobj, "value", len_str);
        json_end(&lobj);
        lobj.buf[lobj.pos - 1] = '\0';
        lobj.pos -= 1;
        json_array_add_object(&ab, lobj.buf);
        json_array_end(&ab);

        JsonBuf jb;
        json_start(&jb);
        json_add_string(&jb, "type", "inspect_result");
        json_add_string(&jb, "class", class_sig);
        json_add_int(&jb, "slot", slot);
        json_add_raw(&jb, "fields", ab.buf);
        json_end(&jb);
        SendToClient(jb.buf);

        jvmti->Deallocate(reinterpret_cast<unsigned char*>(class_sig));
        jni->DeleteLocalRef(obj_class);
        jni->DeleteLocalRef(obj);
        return;
    }

    // Enumerate fields
    jint field_count = 0;
    jfieldID* fields = nullptr;
    jvmti->GetClassFields(obj_class, &field_count, &fields);

    JsonArrayBuf ab;
    json_array_start(&ab);

    for (int i = 0; i < field_count && i < 64; i++) {
        char* fname = nullptr;
        char* fsig = nullptr;
        jint fmod = 0;
        jvmti->GetFieldName(obj_class, fields[i], &fname, &fsig, nullptr);
        jvmti->GetFieldModifiers(obj_class, fields[i], &fmod);

        // Skip static fields
        if (fmod & 0x0008) {
            if (fname) jvmti->Deallocate(reinterpret_cast<unsigned char*>(fname));
            if (fsig) jvmti->Deallocate(reinterpret_cast<unsigned char*>(fsig));
            continue;
        }

        char value_str[512] = "";
        if (fsig && fsig[0]) {
            char sig0 = fsig[0];
            if (sig0 == 'I') {
                jint v = jni->GetIntField(obj, fields[i]);
                snprintf(value_str, sizeof(value_str), "%d", v);
            } else if (sig0 == 'J') {
                jlong v = jni->GetLongField(obj, fields[i]);
                snprintf(value_str, sizeof(value_str), "%lld", (long long)v);
            } else if (sig0 == 'Z') {
                jboolean v = jni->GetBooleanField(obj, fields[i]);
                snprintf(value_str, sizeof(value_str), "%s", v ? "true" : "false");
            } else if (sig0 == 'F') {
                jfloat v = jni->GetFloatField(obj, fields[i]);
                snprintf(value_str, sizeof(value_str), "%f", v);
            } else if (sig0 == 'D') {
                jdouble v = jni->GetDoubleField(obj, fields[i]);
                snprintf(value_str, sizeof(value_str), "%f", v);
            } else if (sig0 == 'B') {
                jbyte v = jni->GetByteField(obj, fields[i]);
                snprintf(value_str, sizeof(value_str), "%d", v);
            } else if (sig0 == 'S') {
                jshort v = jni->GetShortField(obj, fields[i]);
                snprintf(value_str, sizeof(value_str), "%d", v);
            } else if (sig0 == 'C') {
                jchar v = jni->GetCharField(obj, fields[i]);
                snprintf(value_str, sizeof(value_str), "'%c' (%d)", (char)v, v);
            } else if (sig0 == 'L' || sig0 == '[') {
                jobject fval = jni->GetObjectField(obj, fields[i]);
                FormatObjectValue(jni, fval, value_str, sizeof(value_str));
                if (fval) jni->DeleteLocalRef(fval);
            }
        }

        JsonBuf fobj;
        json_start(&fobj);
        json_add_string(&fobj, "name", fname ? fname : "?");
        json_add_string(&fobj, "type", fsig ? fsig : "?");
        json_add_string(&fobj, "value", value_str[0] ? value_str : "<unavailable>");
        json_end(&fobj);
        fobj.buf[fobj.pos - 1] = '\0';
        fobj.pos -= 1;
        json_array_add_object(&ab, fobj.buf);

        if (fname) jvmti->Deallocate(reinterpret_cast<unsigned char*>(fname));
        if (fsig) jvmti->Deallocate(reinterpret_cast<unsigned char*>(fsig));
    }
    if (fields) jvmti->Deallocate(reinterpret_cast<unsigned char*>(fields));
    json_array_end(&ab);

    JsonBuf jb;
    json_start(&jb);
    json_add_string(&jb, "type", "inspect_result");
    json_add_string(&jb, "class", class_sig ? class_sig : "?");
    json_add_int(&jb, "slot", slot);
    json_add_raw(&jb, "fields", ab.buf);
    json_end(&jb);
    SendToClient(jb.buf);

    if (class_sig) jvmti->Deallocate(reinterpret_cast<unsigned char*>(class_sig));
    jni->DeleteLocalRef(obj_class);
    jni->DeleteLocalRef(obj);
}

// eval: call a no-arg method or read a field on an object at a local variable slot
// Syntax: vN.member() for method call, vN.member for field access
static void CmdEval(jvmtiEnv* jvmti, JNIEnv* jni, jthread thread,
                    const char* json) {
    char expr[256] = "";
    if (!json_get_string(json, "expr", expr, sizeof(expr))) {
        SendError("eval: missing 'expr' param");
        return;
    }

    int depth = 0;
    json_get_int(json, "depth", &depth);

    // Parse vN.member or vN.member()
    if (expr[0] != 'v') {
        SendError("eval: expr must start with 'v' (e.g. v3.getAlgorithm())");
        return;
    }
    char* dot = strchr(expr, '.');
    if (!dot) {
        SendError("eval: expr must contain '.' (e.g. v3.getAlgorithm())");
        return;
    }
    *dot = '\0';
    int slot = atoi(expr + 1);
    char* member = dot + 1;

    // Check if it's a method call (has parens)
    bool is_method = false;
    char* paren = strchr(member, '(');
    if (paren) {
        *paren = '\0';  // strip parens
        is_method = true;
    }

    // Reconstruct expression for display
    char display_expr[256];
    snprintf(display_expr, sizeof(display_expr), "v%d.%s%s", slot, member,
             is_method ? "()" : "");

    // Get object from slot
    jobject obj = nullptr;
    jvmtiError err = jvmti->GetLocalObject(thread, depth, slot, &obj);
    if (err != JVMTI_ERROR_NONE || !obj) {
        SendError("eval: GetLocalObject failed (err=%d, slot=%d)", err, slot);
        return;
    }

    jclass obj_class = jni->GetObjectClass(obj);
    if (!obj_class) {
        SendError("eval: GetObjectClass failed for v%d", slot);
        jni->DeleteLocalRef(obj);
        return;
    }

    // --- Try field access first (if no parens, or as fallback) ---
    if (!is_method) {
        jint field_count = 0;
        jfieldID* fields = nullptr;
        jvmti->GetClassFields(obj_class, &field_count, &fields);

        for (int i = 0; i < field_count; i++) {
            char* fname = nullptr;
            char* fsig = nullptr;
            jint fmod = 0;
            jvmti->GetFieldName(obj_class, fields[i], &fname, &fsig, nullptr);
            jvmti->GetFieldModifiers(obj_class, fields[i], &fmod);

            // Skip static fields
            if (fmod & 0x0008) {
                if (fname) jvmti->Deallocate(reinterpret_cast<unsigned char*>(fname));
                if (fsig) jvmti->Deallocate(reinterpret_cast<unsigned char*>(fsig));
                continue;
            }

            if (fname && strcmp(fname, member) == 0) {
                // Found matching field — read value
                char value_str[512] = "";
                char type_sig[256] = "";
                if (fsig) strncpy(type_sig, fsig, sizeof(type_sig) - 1);

                if (fsig && fsig[0]) {
                    char sig0 = fsig[0];
                    if (sig0 == 'I') {
                        jint v = jni->GetIntField(obj, fields[i]);
                        snprintf(value_str, sizeof(value_str), "%d", v);
                    } else if (sig0 == 'J') {
                        jlong v = jni->GetLongField(obj, fields[i]);
                        snprintf(value_str, sizeof(value_str), "%lld", (long long)v);
                    } else if (sig0 == 'Z') {
                        jboolean v = jni->GetBooleanField(obj, fields[i]);
                        snprintf(value_str, sizeof(value_str), "%s", v ? "true" : "false");
                    } else if (sig0 == 'F') {
                        jfloat v = jni->GetFloatField(obj, fields[i]);
                        snprintf(value_str, sizeof(value_str), "%f", v);
                    } else if (sig0 == 'D') {
                        jdouble v = jni->GetDoubleField(obj, fields[i]);
                        snprintf(value_str, sizeof(value_str), "%f", v);
                    } else if (sig0 == 'B') {
                        jbyte v = jni->GetByteField(obj, fields[i]);
                        snprintf(value_str, sizeof(value_str), "%d", v);
                    } else if (sig0 == 'S') {
                        jshort v = jni->GetShortField(obj, fields[i]);
                        snprintf(value_str, sizeof(value_str), "%d", v);
                    } else if (sig0 == 'C') {
                        jchar v = jni->GetCharField(obj, fields[i]);
                        snprintf(value_str, sizeof(value_str), "'%c' (%d)", (char)v, v);
                    } else if (sig0 == 'L' || sig0 == '[') {
                        jobject fval = jni->GetObjectField(obj, fields[i]);
                        FormatObjectValue(jni, fval, value_str, sizeof(value_str));
                        if (fval) jni->DeleteLocalRef(fval);
                    }
                }

                // Send result
                JsonBuf jb;
                json_start(&jb);
                json_add_string(&jb, "type", "eval_result");
                json_add_string(&jb, "expr", display_expr);
                json_add_string(&jb, "return_type", type_sig);
                json_add_string(&jb, "value", value_str[0] ? value_str : "<unavailable>");
                json_end(&jb);
                SendToClient(jb.buf);

                if (fname) jvmti->Deallocate(reinterpret_cast<unsigned char*>(fname));
                if (fsig) jvmti->Deallocate(reinterpret_cast<unsigned char*>(fsig));
                if (fields) jvmti->Deallocate(reinterpret_cast<unsigned char*>(fields));
                jni->DeleteLocalRef(obj_class);
                jni->DeleteLocalRef(obj);
                return;
            }

            if (fname) jvmti->Deallocate(reinterpret_cast<unsigned char*>(fname));
            if (fsig) jvmti->Deallocate(reinterpret_cast<unsigned char*>(fsig));
        }
        if (fields) jvmti->Deallocate(reinterpret_cast<unsigned char*>(fields));

        // Field not found — fall through to method call
    }

    // --- Method call ---
    jint method_count = 0;
    jmethodID* methods = nullptr;
    jvmti->GetClassMethods(obj_class, &method_count, &methods);

    jmethodID target_method = nullptr;
    char ret_sig[256] = "";

    for (int i = 0; i < method_count; i++) {
        char* mname = nullptr;
        char* msig = nullptr;
        jvmti->GetMethodName(methods[i], &mname, &msig, nullptr);

        if (mname && strcmp(mname, member) == 0 && msig) {
            // Check for no-arg method: signature starts with "()"
            if (msig[0] == '(' && msig[1] == ')') {
                target_method = methods[i];
                // Extract return type (everything after ")")
                strncpy(ret_sig, msig + 2, sizeof(ret_sig) - 1);
                if (mname) jvmti->Deallocate(reinterpret_cast<unsigned char*>(mname));
                if (msig) jvmti->Deallocate(reinterpret_cast<unsigned char*>(msig));
                break;
            }
        }

        if (mname) jvmti->Deallocate(reinterpret_cast<unsigned char*>(mname));
        if (msig) jvmti->Deallocate(reinterpret_cast<unsigned char*>(msig));
    }

    if (!target_method) {
        // Also check superclasses via JNI GetMethodID (finds inherited methods)
        jmethodID inherited = nullptr;

        // Try common no-arg signatures
        const char* try_sigs[] = {
            "()Ljava/lang/String;",
            "()I",
            "()J",
            "()Z",
            "()B",
            "()S",
            "()F",
            "()D",
            "()C",
            "()V",
            "()[B",
            "()[C",
            "()[I",
            "()[J",
            "()[Ljava/lang/String;",
            "()Ljava/lang/Object;",
            nullptr
        };

        for (int i = 0; try_sigs[i]; i++) {
            inherited = jni->GetMethodID(obj_class, member, try_sigs[i]);
            if (jni->ExceptionCheck()) {
                jni->ExceptionClear();
                inherited = nullptr;
                continue;
            }
            if (inherited) {
                target_method = inherited;
                // Extract return type after "()"
                strncpy(ret_sig, try_sigs[i] + 2, sizeof(ret_sig) - 1);
                break;
            }
        }
    }

    if (methods) jvmti->Deallocate(reinterpret_cast<unsigned char*>(methods));

    if (!target_method) {
        SendError("eval: method '%s' not found (no-arg) on v%d", member, slot);
        jni->DeleteLocalRef(obj_class);
        jni->DeleteLocalRef(obj);
        return;
    }

    // Call the method based on return type
    char value_str[512] = "";
    char ret_sig0 = ret_sig[0];

    if (ret_sig0 == 'L' || ret_sig0 == '[') {
        jobject result = jni->CallObjectMethod(obj, target_method);
        if (jni->ExceptionCheck()) {
            jthrowable exc = jni->ExceptionOccurred();
            jni->ExceptionClear();
            if (exc) {
                jclass exc_class = jni->GetObjectClass(exc);
                jmethodID getMessage = jni->GetMethodID(exc_class, "getMessage",
                    "()Ljava/lang/String;");
                jstring msg = getMessage ?
                    (jstring)jni->CallObjectMethod(exc, getMessage) : nullptr;
                if (jni->ExceptionCheck()) jni->ExceptionClear();
                const char* msg_str = msg ?
                    jni->GetStringUTFChars(msg, nullptr) : nullptr;
                SendError("eval: %s() threw: %s", member,
                          msg_str ? msg_str : "<exception>");
                if (msg_str) jni->ReleaseStringUTFChars(msg, msg_str);
                if (msg) jni->DeleteLocalRef(msg);
                jni->DeleteLocalRef(exc_class);
                jni->DeleteLocalRef(exc);
            } else {
                SendError("eval: %s() threw an exception", member);
            }
            jni->DeleteLocalRef(obj_class);
            jni->DeleteLocalRef(obj);
            return;
        }
        FormatObjectValue(jni, result, value_str, sizeof(value_str));
        if (result) jni->DeleteLocalRef(result);
    } else if (ret_sig0 == 'I') {
        jint v = jni->CallIntMethod(obj, target_method);
        if (jni->ExceptionCheck()) goto call_exception;
        snprintf(value_str, sizeof(value_str), "%d", v);
    } else if (ret_sig0 == 'J') {
        jlong v = jni->CallLongMethod(obj, target_method);
        if (jni->ExceptionCheck()) goto call_exception;
        snprintf(value_str, sizeof(value_str), "%lld", (long long)v);
    } else if (ret_sig0 == 'Z') {
        jboolean v = jni->CallBooleanMethod(obj, target_method);
        if (jni->ExceptionCheck()) goto call_exception;
        snprintf(value_str, sizeof(value_str), "%s", v ? "true" : "false");
    } else if (ret_sig0 == 'F') {
        jfloat v = jni->CallFloatMethod(obj, target_method);
        if (jni->ExceptionCheck()) goto call_exception;
        snprintf(value_str, sizeof(value_str), "%f", v);
    } else if (ret_sig0 == 'D') {
        jdouble v = jni->CallDoubleMethod(obj, target_method);
        if (jni->ExceptionCheck()) goto call_exception;
        snprintf(value_str, sizeof(value_str), "%f", v);
    } else if (ret_sig0 == 'B') {
        jbyte v = jni->CallByteMethod(obj, target_method);
        if (jni->ExceptionCheck()) goto call_exception;
        snprintf(value_str, sizeof(value_str), "%d", v);
    } else if (ret_sig0 == 'S') {
        jshort v = jni->CallShortMethod(obj, target_method);
        if (jni->ExceptionCheck()) goto call_exception;
        snprintf(value_str, sizeof(value_str), "%d", v);
    } else if (ret_sig0 == 'C') {
        jchar v = jni->CallCharMethod(obj, target_method);
        if (jni->ExceptionCheck()) goto call_exception;
        snprintf(value_str, sizeof(value_str), "'%c' (%d)", (char)v, v);
    } else if (ret_sig0 == 'V') {
        jni->CallVoidMethod(obj, target_method);
        if (jni->ExceptionCheck()) goto call_exception;
        snprintf(value_str, sizeof(value_str), "<void>");
    } else {
        snprintf(value_str, sizeof(value_str), "<unknown return type: %s>", ret_sig);
    }

    goto eval_send_result;

call_exception:
    {
        jthrowable exc = jni->ExceptionOccurred();
        jni->ExceptionClear();
        if (exc) {
            jclass exc_class = jni->GetObjectClass(exc);
            jmethodID getMessage = jni->GetMethodID(exc_class, "getMessage",
                "()Ljava/lang/String;");
            jstring msg = getMessage ?
                (jstring)jni->CallObjectMethod(exc, getMessage) : nullptr;
            if (jni->ExceptionCheck()) jni->ExceptionClear();
            const char* msg_str = msg ?
                jni->GetStringUTFChars(msg, nullptr) : nullptr;
            SendError("eval: %s() threw: %s", member,
                      msg_str ? msg_str : "<exception>");
            if (msg_str) jni->ReleaseStringUTFChars(msg, msg_str);
            if (msg) jni->DeleteLocalRef(msg);
            jni->DeleteLocalRef(exc_class);
            jni->DeleteLocalRef(exc);
        } else {
            SendError("eval: %s() threw an exception", member);
        }
        jni->DeleteLocalRef(obj_class);
        jni->DeleteLocalRef(obj);
        return;
    }

eval_send_result:
    {
        JsonBuf jb;
        json_start(&jb);
        json_add_string(&jb, "type", "eval_result");
        json_add_string(&jb, "expr", display_expr);
        json_add_string(&jb, "return_type", ret_sig);
        json_add_string(&jb, "value", value_str[0] ? value_str : "<unavailable>");
        json_end(&jb);
        SendToClient(jb.buf);
    }

    jni->DeleteLocalRef(obj_class);
    jni->DeleteLocalRef(obj);
}

// hexdump: read a byte[]/char[]/short[] array from a local variable slot and send base64
static void CmdHexdump(jvmtiEnv* jvmti, JNIEnv* jni, jthread thread,
                       const char* json) {
    int slot = -1;
    if (!json_get_int(json, "slot", &slot)) {
        SendError("hexdump: missing 'slot' param");
        return;
    }

    int depth = 0;
    json_get_int(json, "depth", &depth);

    jobject obj = nullptr;
    jvmtiError err = jvmti->GetLocalObject(thread, depth, slot, &obj);
    if (err != JVMTI_ERROR_NONE || !obj) {
        SendError("hexdump: GetLocalObject failed (err=%d, slot=%d)", err, slot);
        return;
    }

    // Check what type we have
    jclass obj_class = jni->GetObjectClass(obj);
    char* class_sig = nullptr;
    jvmti->GetClassSignature(obj_class, &class_sig, nullptr);

    const unsigned char* data = nullptr;
    int data_len = 0;
    jbyteArray byte_arr = nullptr;
    jcharArray char_arr = nullptr;

    if (class_sig && strcmp(class_sig, "[B") == 0) {
        // byte[]
        byte_arr = (jbyteArray)obj;
        data_len = jni->GetArrayLength(byte_arr);
        jbyte* elems = jni->GetByteArrayElements(byte_arr, nullptr);
        if (elems) {
            data = (const unsigned char*)elems;
        }
    } else if (class_sig && strcmp(class_sig, "[C") == 0) {
        // char[] — copy as raw bytes (UTF-16)
        char_arr = (jcharArray)obj;
        int arr_len = jni->GetArrayLength(char_arr);
        jchar* elems = jni->GetCharArrayElements(char_arr, nullptr);
        if (elems) {
            data = (const unsigned char*)elems;
            data_len = arr_len * 2;
        }
    } else {
        // Try to see if it's a String — call getBytes()
        jclass string_class = jni->FindClass("java/lang/String");
        if (string_class && jni->IsInstanceOf(obj, string_class)) {
            // Get UTF-8 bytes
            const char* utf = jni->GetStringUTFChars((jstring)obj, nullptr);
            if (utf) {
                data_len = strlen(utf);
                // Need to copy since we release before sending
                unsigned char* copy = (unsigned char*)malloc(data_len);
                if (copy) {
                    memcpy(copy, utf, data_len);
                    data = copy;
                }
                jni->ReleaseStringUTFChars((jstring)obj, utf);

                // Encode and send
                int b64_len = ((data_len + 2) / 3) * 4 + 1;
                char* b64 = (char*)malloc(b64_len);
                if (b64 && data) {
                    base64_encode(data, data_len, b64, b64_len);
                    JsonBuf jb;
                    json_start(&jb);
                    json_add_string(&jb, "type", "hexdump_result");
                    json_add_int(&jb, "slot", slot);
                    json_add_string(&jb, "array_type", "String (UTF-8)");
                    json_add_int(&jb, "length", data_len);
                    json_add_string(&jb, "data_b64", b64);
                    json_end(&jb);
                    SendToClient(jb.buf);
                    free(b64);
                }
                free((void*)data);
                if (class_sig) jvmti->Deallocate(reinterpret_cast<unsigned char*>(class_sig));
                jni->DeleteLocalRef(obj_class);
                if (string_class) jni->DeleteLocalRef(string_class);
                jni->DeleteLocalRef(obj);
                return;
            }
            if (string_class) jni->DeleteLocalRef(string_class);
        } else {
            if (string_class) jni->DeleteLocalRef(string_class);
        }

        SendError("hexdump: v%d is not byte[]/char[]/String (type=%s)", slot,
                  class_sig ? class_sig : "?");
        if (class_sig) jvmti->Deallocate(reinterpret_cast<unsigned char*>(class_sig));
        jni->DeleteLocalRef(obj_class);
        jni->DeleteLocalRef(obj);
        return;
    }

    if (!data || data_len <= 0) {
        SendError("hexdump: empty or null array at v%d", slot);
        if (class_sig) jvmti->Deallocate(reinterpret_cast<unsigned char*>(class_sig));
        jni->DeleteLocalRef(obj_class);
        jni->DeleteLocalRef(obj);
        return;
    }

    // Cap at 64KB to avoid huge transfers
    int send_len = data_len > 65536 ? 65536 : data_len;

    // Base64 encode
    int b64_len = ((send_len + 2) / 3) * 4 + 1;
    char* b64 = (char*)malloc(b64_len);
    if (!b64) {
        SendError("hexdump: out of memory for base64");
        if (class_sig && strcmp(class_sig, "[B") == 0)
            jni->ReleaseByteArrayElements(byte_arr, (jbyte*)data, JNI_ABORT);
        if (class_sig && strcmp(class_sig, "[C") == 0)
            jni->ReleaseCharArrayElements(char_arr, (jchar*)data, JNI_ABORT);
        if (class_sig) jvmti->Deallocate(reinterpret_cast<unsigned char*>(class_sig));
        jni->DeleteLocalRef(obj_class);
        jni->DeleteLocalRef(obj);
        return;
    }

    base64_encode(data, send_len, b64, b64_len);

    const char* type_str = "[B";
    if (class_sig && strcmp(class_sig, "[C") == 0) type_str = "[C";

    // If fits in JsonBuf use it; otherwise malloc
    int b64_actual = strlen(b64);
    if (b64_actual < 14000) {
        JsonBuf jb;
        json_start(&jb);
        json_add_string(&jb, "type", "hexdump_result");
        json_add_int(&jb, "slot", slot);
        json_add_string(&jb, "array_type", type_str);
        json_add_int(&jb, "length", data_len);
        json_add_string(&jb, "data_b64", b64);
        json_end(&jb);
        SendToClient(jb.buf);
    } else {
        // Large: malloc buffer
        int buf_size = b64_actual + 512;
        char* buf = (char*)malloc(buf_size);
        if (buf) {
            int pos = snprintf(buf, buf_size,
                "{\"type\":\"hexdump_result\",\"slot\":%d,\"array_type\":\"%s\",\"length\":%d,\"data_b64\":\"",
                slot, type_str, data_len);
            memcpy(buf + pos, b64, b64_actual);
            pos += b64_actual;
            buf[pos++] = '"';
            buf[pos++] = '}';
            buf[pos++] = '\n';
            buf[pos] = '\0';
            SendToClient(buf);
            free(buf);
        } else {
            SendError("hexdump: out of memory for large buffer");
        }
    }

    free(b64);

    // Release array elements
    if (class_sig && strcmp(class_sig, "[B") == 0)
        jni->ReleaseByteArrayElements(byte_arr, (jbyte*)data, JNI_ABORT);
    if (class_sig && strcmp(class_sig, "[C") == 0)
        jni->ReleaseCharArrayElements(char_arr, (jchar*)data, JNI_ABORT);

    if (class_sig) jvmti->Deallocate(reinterpret_cast<unsigned char*>(class_sig));
    jni->DeleteLocalRef(obj_class);
    jni->DeleteLocalRef(obj);
}

// ---------------------------------------------------------------------------
// Native memory dump (global command, runs on socket thread)
// ---------------------------------------------------------------------------

static void CmdMemDump(jvmtiEnv* jvmti, JNIEnv* jni, const char* json) {
    long long addr_ll = 0, size_ll = 0;
    if (!json_get_long(json, "addr", &addr_ll) || !json_get_long(json, "size", &size_ll)) {
        SendError("memdump: missing addr or size");
        return;
    }
    uintptr_t addr = (uintptr_t)(unsigned long long)addr_ll;
    size_t size = (size_t)(unsigned long long)size_ll;

    const size_t kMaxInlineSize = 16 * 1024 * 1024; // 16 MB
    if (size == 0 || size > kMaxInlineSize) {
        SendError("memdump: size must be 1..16MB (got %zu)", size);
        return;
    }

    char path[256] = "";
    json_get_string(json, "path", path, sizeof(path));
    bool has_path = path[0] != '\0';

    uint8_t* buf = (uint8_t*)malloc(size);
    if (!buf) {
        SendError("memdump: malloc(%zu) failed", size);
        return;
    }

    // Safe read: /proc/self/mem returns EIO on unmapped pages instead of SIGSEGV
    int memfd = open("/proc/self/mem", O_RDONLY);
    if (memfd < 0) {
        free(buf);
        SendError("memdump: open /proc/self/mem failed: %s", strerror(errno));
        return;
    }
    ssize_t nread = pread(memfd, buf, size, (off_t)addr);
    close(memfd);

    if (nread < 0) {
        free(buf);
        SendError("memdump: pread at 0x%llx failed: %s",
                  (unsigned long long)addr, strerror(errno));
        return;
    }

    if (has_path) {
        FILE* f = fopen(path, "wb");
        if (!f) {
            free(buf);
            SendError("memdump: fopen(%s) failed: %s", path, strerror(errno));
            return;
        }
        fwrite(buf, 1, (size_t)nread, f);
        fclose(f);
        free(buf);
        JsonBuf jb;
        json_start(&jb);
        json_add_string(&jb, "type", "memdump_result");
        json_add_long(&jb, "addr", addr_ll);
        json_add_long(&jb, "size", (long long)nread);
        json_add_string(&jb, "path", path);
        json_end(&jb);
        SendToClient(jb.buf);
    } else {
        // Inline: base64-encode + build JSON manually (same pattern as SendDexLoaded)
        int b64_len = (((int)nread + 2) / 3) * 4 + 1;
        int out_size = b64_len + 256;
        char* b64 = (char*)malloc(b64_len);
        char* out = (char*)malloc(out_size);
        if (!b64 || !out) {
            free(buf); free(b64); free(out);
            SendError("memdump: OOM for base64 encoding");
            return;
        }
        base64_encode(buf, (int)nread, b64, b64_len);
        free(buf);

        int pos = snprintf(out, out_size,
            "{\"type\":\"memdump_result\",\"addr\":%lld,\"size\":%zd,\"data_b64\":\"",
            addr_ll, nread);
        int b64_actual = (int)strlen(b64);
        if (pos + b64_actual + 4 <= out_size) {
            memcpy(out + pos, b64, b64_actual);
            pos += b64_actual;
        }
        free(b64);
        if (pos + 3 <= out_size) {
            out[pos++] = '"';
            out[pos++] = '}';
            out[pos++] = '\n';
            out[pos] = '\0';
        }
        SendToClient(out);
        free(out);
    }
}

// ---------------------------------------------------------------------------
// Milestone 3: Heap search (global command, runs on socket thread)
// ---------------------------------------------------------------------------

static void CmdHeap(jvmtiEnv* jvmti, JNIEnv* jni, const char* json) {
    if (!g_dbg.cap_tag_objects) {
        SendError("Heap search not available on this device/Android version (no can_tag_objects)");
        return;
    }
    char class_sig[256];
    if (!json_get_string(json, "class", class_sig, sizeof(class_sig))) {
        JsonBuf jb;
        json_start(&jb);
        json_add_string(&jb, "type", "error");
        json_add_string(&jb, "msg", "missing 'class' param");
        json_end(&jb);
        SendToClient(jb.buf);
        return;
    }

    int max_count = 10;
    json_get_int(json, "max", &max_count);
    if (max_count <= 0) max_count = 10;
    if (max_count > 100) max_count = 100;

    jclass klass = FindClassBySig(jvmti, jni, class_sig);
    if (!klass) {
        JsonBuf jb;
        json_start(&jb);
        json_add_string(&jb, "type", "error");
        json_add_string(&jb, "msg", "class not found");
        json_end(&jb);
        SendToClient(jb.buf);
        return;
    }

    // Tag all instances
    const jlong kTag = 0xDEADBEEF;
    jvmtiError err = jvmti->IterateOverInstancesOfClass(
        klass, JVMTI_HEAP_OBJECT_EITHER,
        [](jlong class_tag, jlong size, jlong* tag_ptr, void* user_data) -> jvmtiIterationControl {
            *tag_ptr = *(jlong*)user_data;
            return JVMTI_ITERATION_CONTINUE;
        },
        (void*)&kTag);

    if (err != JVMTI_ERROR_NONE) {
        jni->DeleteGlobalRef(klass);
        JsonBuf jb;
        json_start(&jb);
        json_add_string(&jb, "type", "error");
        json_add_string(&jb, "msg", "IterateOverInstancesOfClass failed");
        json_end(&jb);
        SendToClient(jb.buf);
        return;
    }

    // Retrieve tagged objects. Push a local frame so all refs returned by
    // GetObjectsWithTags live in an inner frame and are batch-released by
    // PopLocalFrame — avoids "index outside area" DeleteLocalRef failures on
    // the socket thread which has no managed Java frames.
    jni->PushLocalFrame(128);
    jlong tags[] = { kTag };
    jint count = 0;
    jobject* objects = nullptr;
    jlong* obj_tags = nullptr;
    err = jvmti->GetObjectsWithTags(1, tags, &count, &objects, &obj_tags);

    if (err != JVMTI_ERROR_NONE) {
        jni->PopLocalFrame(nullptr);
        jni->DeleteGlobalRef(klass);
        JsonBuf jb;
        json_start(&jb);
        json_add_string(&jb, "type", "error");
        json_add_string(&jb, "msg", "GetObjectsWithTags failed");
        json_end(&jb);
        SendToClient(jb.buf);
        return;
    }

    // Clear tags and build result
    JsonArrayBuf ab;
    json_array_start(&ab);

    int reported = 0;
    for (int i = 0; i < count && reported < max_count; i++) {
        // Clear the tag
        jvmti->SetTag(objects[i], 0);

        char val[512];
        FormatObjectValue(jni, objects[i], val, sizeof(val));

        JsonBuf obj;
        json_start(&obj);
        json_add_int(&obj, "index", reported);
        json_add_string(&obj, "value", val);
        json_end(&obj);
        obj.buf[obj.pos - 1] = '\0';
        obj.pos -= 1;
        json_array_add_object(&ab, obj.buf);

        reported++;
    }
    // Clear remaining tags
    for (int i = reported; i < count; i++) {
        jvmti->SetTag(objects[i], 0);
    }

    jni->PopLocalFrame(nullptr);  // releases all GetObjectsWithTags local refs at once
    if (objects) jvmti->Deallocate(reinterpret_cast<unsigned char*>(objects));
    if (obj_tags) jvmti->Deallocate(reinterpret_cast<unsigned char*>(obj_tags));
    jni->DeleteGlobalRef(klass);

    json_array_end(&ab);

    JsonBuf jb;
    json_start(&jb);
    json_add_string(&jb, "type", "heap_result");
    json_add_string(&jb, "class", class_sig);
    json_add_int(&jb, "total", count);
    json_add_int(&jb, "reported", reported);
    json_add_raw(&jb, "objects", ab.buf);
    json_end(&jb);
    SendToClient(jb.buf);
}

// ---------------------------------------------------------------------------
// Heap string search — find live String objects matching a pattern
// ---------------------------------------------------------------------------

struct HeapStrTagData {
    jlong tag;
    int count;
    int max_tag;
};

static void CmdHeapStrings(jvmtiEnv* jvmti, JNIEnv* jni, const char* json) {
    if (!g_dbg.cap_tag_objects) {
        SendError("Heap string search not available (no can_tag_objects)");
        return;
    }

    char pattern[256] = "";
    if (!json_get_string(json, "pattern", pattern, sizeof(pattern)) || pattern[0] == '\0') {
        SendError("missing 'pattern' param");
        return;
    }

    int max_results = 200;
    json_get_int(json, "max", &max_results);
    if (max_results <= 0) max_results = 200;
    if (max_results > 500) max_results = 500;

    // Find java.lang.String class
    jclass str_class = jni->FindClass("java/lang/String");
    if (!str_class) {
        SendError("Cannot find java.lang.String");
        return;
    }

    // Tag all String instances (cap at 50000 to avoid excessive memory)
    const jlong kTag = 0xDEAD5742;
    HeapStrTagData tdata = { kTag, 0, 5000 };  // cap at 5000 to limit local ref pressure

    jvmtiError err = jvmti->IterateOverInstancesOfClass(
        str_class, JVMTI_HEAP_OBJECT_EITHER,
        [](jlong class_tag, jlong size, jlong* tag_ptr, void* user_data) -> jvmtiIterationControl {
            HeapStrTagData* d = (HeapStrTagData*)user_data;
            if (d->count >= d->max_tag) return JVMTI_ITERATION_ABORT;
            *tag_ptr = d->tag;
            d->count++;
            return JVMTI_ITERATION_CONTINUE;
        },
        &tdata);

    if (err != JVMTI_ERROR_NONE) {
        jni->DeleteLocalRef(str_class);
        SendError("IterateOverInstancesOfClass failed (%d)", err);
        return;
    }

    int total_strings = tdata.count;

    // Retrieve tagged objects. Push a local frame so all refs returned by
    // GetObjectsWithTags live in an inner frame and are batch-released by
    // PopLocalFrame — avoids "index outside area" DeleteLocalRef failures on
    // the socket thread which has no managed Java frames.
    jni->PushLocalFrame(128);
    jlong tags[] = { kTag };
    jint count = 0;
    jobject* objects = nullptr;
    jlong* obj_tags = nullptr;
    err = jvmti->GetObjectsWithTags(1, tags, &count, &objects, &obj_tags);

    if (err != JVMTI_ERROR_NONE) {
        jni->PopLocalFrame(nullptr);
        jni->DeleteLocalRef(str_class);
        SendError("GetObjectsWithTags failed (%d)", err);
        return;
    }

    // Build lowercase pattern for case-insensitive matching
    char pat_lower[256];
    int plen = 0;
    for (int i = 0; pattern[i] && i < 255; i++) {
        pat_lower[i] = (pattern[i] >= 'A' && pattern[i] <= 'Z') ? (pattern[i] + 32) : pattern[i];
        plen++;
    }
    pat_lower[plen] = '\0';

    // Filter matching strings
    JsonArrayBuf ab;
    json_array_start(&ab);

    int matches = 0;
    for (int i = 0; i < count; i++) {
        jvmti->SetTag(objects[i], 0);  // clear tag

        if (matches >= max_results) continue;

        const char* s = jni->GetStringUTFChars((jstring)objects[i], nullptr);
        if (s) {
            // Case-insensitive substring search
            int slen = strlen(s);
            bool found = false;
            if (plen <= slen) {
                for (int j = 0; j <= slen - plen; j++) {
                    bool match = true;
                    for (int k = 0; k < plen; k++) {
                        char c = s[j + k];
                        if (c >= 'A' && c <= 'Z') c += 32;
                        if (c != pat_lower[k]) { match = false; break; }
                    }
                    if (match) { found = true; break; }
                }
            }

            if (found) {
                char display[512];
                if (slen > 200) {
                    snprintf(display, sizeof(display), "%.200s...", s);
                } else {
                    snprintf(display, sizeof(display), "%s", s);
                }

                JsonBuf obj;
                json_start(&obj);
                json_add_int(&obj, "index", matches);
                json_add_string(&obj, "value", display);
                json_end(&obj);
                obj.buf[obj.pos - 1] = '\0';  // remove trailing newline
                obj.pos -= 1;
                json_array_add_object(&ab, obj.buf);
                matches++;
            }

            jni->ReleaseStringUTFChars((jstring)objects[i], s);
        }
    }

    jni->PopLocalFrame(nullptr);  // releases all GetObjectsWithTags local refs at once
    if (objects) jvmti->Deallocate(reinterpret_cast<unsigned char*>(objects));
    if (obj_tags) jvmti->Deallocate(reinterpret_cast<unsigned char*>(obj_tags));
    jni->DeleteLocalRef(str_class);

    json_array_end(&ab);

    JsonBuf jb;
    json_start(&jb);
    json_add_string(&jb, "type", "heap_strings_result");
    json_add_string(&jb, "pattern", pattern);
    json_add_int(&jb, "total_strings", total_strings);
    json_add_int(&jb, "matches", matches);
    json_add_raw(&jb, "strings", ab.buf);
    json_end(&jb);
    SendToClient(jb.buf);
}

// ---------------------------------------------------------------------------
// Dynamic DEX interception — extract DEX bytes from device and send to server
// ---------------------------------------------------------------------------

// Max file size for dex_read (20 MB)
static const int kMaxDexFileSize = 20 * 1024 * 1024;

// Send a dex_loaded event with base64-encoded DEX bytes.
// Uses malloc'd buffer because DEX files can be 100KB-10MB (far exceeds JsonBuf 16KB).
static void SendDexLoaded(const char* source, const char* path,
                          const unsigned char* data, int size) {
    // Base64 output size: ceil(size/3)*4
    int b64_len = ((size + 2) / 3) * 4 + 1;

    // Build JSON manually: {"type":"dex_loaded","source":"...","path":"...","size":N,"dex_b64":"..."}
    // Header + b64 + 512 bytes overhead for JSON keys and values
    int buf_size = b64_len + 512 + (path ? (int)strlen(path) : 0);
    char* buf = (char*)malloc(buf_size);
    if (!buf) {
        ALOGE("[DEX] malloc(%d) failed for dex_loaded", buf_size);
        SendError("dex_loaded: out of memory (dex size=%d)", size);
        return;
    }

    char* b64 = (char*)malloc(b64_len);
    if (!b64) {
        free(buf);
        ALOGE("[DEX] malloc(%d) failed for base64", b64_len);
        SendError("dex_loaded: out of memory for base64 (dex size=%d)", size);
        return;
    }

    base64_encode(data, size, b64, b64_len);

    int pos = snprintf(buf, buf_size,
        "{\"type\":\"dex_loaded\",\"source\":\"%s\",\"path\":\"%s\",\"size\":%d,\"dex_b64\":\"",
        source, path ? path : "", size);

    // Copy base64 data
    int b64_actual = strlen(b64);
    if (pos + b64_actual + 4 < buf_size) {
        memcpy(buf + pos, b64, b64_actual);
        pos += b64_actual;
    }
    free(b64);

    // Close JSON
    if (pos + 3 < buf_size) {
        buf[pos++] = '"';
        buf[pos++] = '}';
        buf[pos++] = '\n';
        buf[pos] = '\0';
    }

    ALOGI("[DEX] Sending dex_loaded: source=%s path=%s size=%d b64_len=%d",
          source, path ? path : "(memory)", size, b64_actual);

    SendToClient(buf);
    free(buf);
}

// dex_read: read a DEX/JAR/APK file from device filesystem by path (global command)
static void CmdDexRead(jvmtiEnv* jvmti, JNIEnv* jni, const char* json) {
    char path[1024] = "";
    if (!json_get_string(json, "path", path, sizeof(path)) || path[0] == '\0') {
        SendError("dex_read: missing 'path' param");
        return;
    }

    ALOGI("[DEX] dex_read: opening %s", path);

    FILE* f = fopen(path, "rb");
    if (!f) {
        SendError("dex_read: cannot open '%s': %s", path, strerror(errno));
        return;
    }

    // Get file size
    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (file_size <= 0) {
        fclose(f);
        SendError("dex_read: file '%s' is empty or unreadable", path);
        return;
    }
    if (file_size > kMaxDexFileSize) {
        fclose(f);
        SendError("dex_read: file '%s' too large (%ld bytes, max %d)", path, file_size, kMaxDexFileSize);
        return;
    }

    unsigned char* data = (unsigned char*)malloc(file_size);
    if (!data) {
        fclose(f);
        SendError("dex_read: malloc(%ld) failed", file_size);
        return;
    }

    size_t nread = fread(data, 1, file_size, f);
    fclose(f);

    if ((long)nread != file_size) {
        free(data);
        SendError("dex_read: read %zu of %ld bytes from '%s'", nread, file_size, path);
        return;
    }

    SendDexLoaded("file", path, data, (int)file_size);
    free(data);
}

// ssl_get_tm_classes: extract runtime class signatures of TrustManager[] elements
// from the current SSLContext.init frame. Used by bypass-ssl to identify obfuscated
// custom TrustManager implementations.
static void CmdSslGetTmClasses(jvmtiEnv* jvmti, JNIEnv* jni, jthread thread,
                                jmethodID method) {
    // SSLContext.init(KeyManager[], TrustManager[], SecureRandom) — instance method
    // Dalvik param slots: p0=this, p1=km[], p2=tm[], p3=random
    // tm[] slot = max_locals - args_size + 2
    jint max_locals = 0, args_size = 0;
    jvmti->GetMaxLocals(method, &max_locals);
    jvmti->GetArgumentsSize(method, &args_size);
    int tm_slot = max_locals - args_size + 2;

    jobject tm_array = nullptr;
    jvmtiError err = jvmti->GetLocalObject(thread, 0, tm_slot, &tm_array);

    JsonArrayBuf ab;
    json_array_start(&ab);

    if (err == JVMTI_ERROR_NONE && tm_array) {
        jint len = jni->GetArrayLength(reinterpret_cast<jarray>(tm_array));
        for (jint i = 0; i < len; i++) {
            jobject elem = jni->GetObjectArrayElement(
                reinterpret_cast<jobjectArray>(tm_array), i);
            if (!elem) continue;
            jclass cls = jni->GetObjectClass(elem);
            char* sig = nullptr;
            jvmti->GetClassSignature(cls, &sig, nullptr);
            if (sig) {
                char quoted[512];
                snprintf(quoted, sizeof(quoted), "\"%s\"", sig);
                json_array_add_object(&ab, quoted);
                jvmti->Deallocate(reinterpret_cast<unsigned char*>(sig));
            }
            jni->DeleteLocalRef(cls);
            jni->DeleteLocalRef(elem);
        }
        jni->DeleteLocalRef(tm_array);
    }

    json_array_end(&ab);

    JsonBuf jb;
    json_start(&jb);
    json_add_string(&jb, "type", "tm_classes");
    json_add_raw(&jb, "classes", ab.buf);
    json_end(&jb);
    SendToClient(jb.buf);
}

// dex_dump: extract DEX from current DexClassLoader/InMemoryDexClassLoader frame (suspended command)
static void CmdDexDump(jvmtiEnv* jvmti, JNIEnv* jni, jthread thread,
                       jmethodID method, jlocation location) {
    // Get current class and method info
    char* class_sig = nullptr;
    char* mname = nullptr;
    char* msig = nullptr;
    if (!GetMethodInfo(jvmti, method, &class_sig, &mname, &msig)) {
        SendError("dex_dump: cannot get method info");
        return;
    }

    ALOGI("[DEX] dex_dump: at %s.%s%s", class_sig, mname, msig);

    bool is_dex_class_loader = (strstr(class_sig, "DexClassLoader") != nullptr);
    bool is_inmemory_loader = (strstr(class_sig, "InMemoryDexClassLoader") != nullptr);

    if (!is_dex_class_loader && !is_inmemory_loader) {
        SendError("dex_dump: not at a DEX loading method (class=%s, method=%s)", class_sig, mname);
        FreeMethodInfo(jvmti, class_sig, mname, msig);
        return;
    }

    if (is_inmemory_loader) {
        // InMemoryDexClassLoader.<init>(ByteBuffer dexBuffer, ClassLoader parent)
        // or InMemoryDexClassLoader.<init>(ByteBuffer[] dexBuffers, ClassLoader parent)
        // Try to find the ByteBuffer argument

        // Try GetLocalVariableTable first
        jint var_count = 0;
        jvmtiLocalVariableEntry* var_table = nullptr;
        bool have_table = (jvmti->GetLocalVariableTable(method, &var_count, &var_table)
                           == JVMTI_ERROR_NONE);

        jobject buffer = nullptr;
        if (have_table && var_table) {
            for (int i = 0; i < var_count; i++) {
                if (var_table[i].signature &&
                    strcmp(var_table[i].signature, "Ljava/nio/ByteBuffer;") == 0) {
                    jvmti->GetLocalObject(thread, 0, var_table[i].slot, &buffer);
                    break;
                }
            }
            // Free table
            for (int i = 0; i < var_count; i++) {
                if (var_table[i].name) jvmti->Deallocate(reinterpret_cast<unsigned char*>(var_table[i].name));
                if (var_table[i].signature) jvmti->Deallocate(reinterpret_cast<unsigned char*>(var_table[i].signature));
                if (var_table[i].generic_signature) jvmti->Deallocate(reinterpret_cast<unsigned char*>(var_table[i].generic_signature));
            }
            jvmti->Deallocate(reinterpret_cast<unsigned char*>(var_table));
        }

        // Fallback: scan slots for ByteBuffer object
        if (!buffer) {
            jclass bbCls = jni->FindClass("java/nio/ByteBuffer");
            if (bbCls) {
                jint max_locals = 0;
                jvmti->GetMaxLocals(method, &max_locals);
                for (int slot = 0; slot < max_locals && !buffer; slot++) {
                    jobject obj = nullptr;
                    if (jvmti->GetLocalObject(thread, 0, slot, &obj) == JVMTI_ERROR_NONE && obj) {
                        if (jni->IsInstanceOf(obj, bbCls)) {
                            buffer = obj;
                        } else {
                            jni->DeleteLocalRef(obj);
                        }
                    }
                }
                jni->DeleteLocalRef(bbCls);
            }
        }

        if (!buffer) {
            SendError("dex_dump: cannot find ByteBuffer argument in InMemoryDexClassLoader");
            FreeMethodInfo(jvmti, class_sig, mname, msig);
            return;
        }

        // Extract bytes from ByteBuffer via JNI
        jclass bbCls = jni->GetObjectClass(buffer);
        jmethodID remaining = jni->GetMethodID(bbCls, "remaining", "()I");
        jmethodID rewind = jni->GetMethodID(bbCls, "rewind", "()Ljava/nio/Buffer;");
        jmethodID getBulk = jni->GetMethodID(bbCls, "get", "([B)Ljava/nio/ByteBuffer;");

        if (!remaining || !rewind || !getBulk) {
            SendError("dex_dump: cannot find ByteBuffer methods");
            jni->DeleteLocalRef(bbCls);
            jni->DeleteLocalRef(buffer);
            FreeMethodInfo(jvmti, class_sig, mname, msig);
            return;
        }

        // Rewind to start, get remaining bytes
        jni->CallObjectMethod(buffer, rewind);
        if (jni->ExceptionCheck()) { jni->ExceptionClear(); }
        jint size = jni->CallIntMethod(buffer, remaining);
        if (jni->ExceptionCheck()) { jni->ExceptionClear(); size = 0; }

        if (size <= 0 || size > kMaxDexFileSize) {
            SendError("dex_dump: ByteBuffer size invalid (%d)", size);
            jni->DeleteLocalRef(bbCls);
            jni->DeleteLocalRef(buffer);
            FreeMethodInfo(jvmti, class_sig, mname, msig);
            return;
        }

        jbyteArray arr = jni->NewByteArray(size);
        if (!arr) {
            SendError("dex_dump: NewByteArray(%d) failed", size);
            jni->DeleteLocalRef(bbCls);
            jni->DeleteLocalRef(buffer);
            FreeMethodInfo(jvmti, class_sig, mname, msig);
            return;
        }

        jni->CallObjectMethod(buffer, getBulk, arr);
        if (jni->ExceptionCheck()) { jni->ExceptionClear(); }

        jbyte* bytes = jni->GetByteArrayElements(arr, nullptr);
        if (bytes) {
            SendDexLoaded("memory", nullptr, (const unsigned char*)bytes, size);
            jni->ReleaseByteArrayElements(arr, bytes, JNI_ABORT);
        } else {
            SendError("dex_dump: GetByteArrayElements failed");
        }

        // Rewind again so the original call proceeds correctly
        jni->CallObjectMethod(buffer, rewind);
        if (jni->ExceptionCheck()) { jni->ExceptionClear(); }

        jni->DeleteLocalRef(arr);
        jni->DeleteLocalRef(bbCls);
        jni->DeleteLocalRef(buffer);

    } else {
        // DexClassLoader.<init>(String dexPath, String optimizedDir, String libPath, ClassLoader parent)
        // Find the dexPath String argument

        // Try GetLocalVariableTable first
        jint var_count = 0;
        jvmtiLocalVariableEntry* var_table = nullptr;
        bool have_table = (jvmti->GetLocalVariableTable(method, &var_count, &var_table)
                           == JVMTI_ERROR_NONE);

        jobject dex_path_obj = nullptr;
        if (have_table && var_table) {
            for (int i = 0; i < var_count; i++) {
                if (var_table[i].name && var_table[i].signature &&
                    (strcmp(var_table[i].name, "dexPath") == 0 ||
                     strcmp(var_table[i].name, "dexFile") == 0) &&
                    strcmp(var_table[i].signature, "Ljava/lang/String;") == 0) {
                    jvmti->GetLocalObject(thread, 0, var_table[i].slot, &dex_path_obj);
                    break;
                }
            }
            // Free table
            for (int i = 0; i < var_count; i++) {
                if (var_table[i].name) jvmti->Deallocate(reinterpret_cast<unsigned char*>(var_table[i].name));
                if (var_table[i].signature) jvmti->Deallocate(reinterpret_cast<unsigned char*>(var_table[i].signature));
                if (var_table[i].generic_signature) jvmti->Deallocate(reinterpret_cast<unsigned char*>(var_table[i].generic_signature));
            }
            jvmti->Deallocate(reinterpret_cast<unsigned char*>(var_table));
        }

        // Fallback: scan slots for the first String object (slot after "this")
        if (!dex_path_obj) {
            jclass strCls = jni->FindClass("java/lang/String");
            if (strCls) {
                jint max_locals = 0;
                jvmti->GetMaxLocals(method, &max_locals);
                bool found_this = false;
                for (int slot = 0; slot < max_locals && !dex_path_obj; slot++) {
                    jobject obj = nullptr;
                    if (jvmti->GetLocalObject(thread, 0, slot, &obj) == JVMTI_ERROR_NONE && obj) {
                        if (jni->IsInstanceOf(obj, strCls)) {
                            if (found_this) {
                                // First String after "this" = dexPath
                                dex_path_obj = obj;
                            } else {
                                jni->DeleteLocalRef(obj);
                            }
                        } else {
                            // Assume first non-String object is "this"
                            if (!found_this) found_this = true;
                            jni->DeleteLocalRef(obj);
                        }
                    }
                }
                jni->DeleteLocalRef(strCls);
            }
        }

        if (!dex_path_obj) {
            SendError("dex_dump: cannot find dexPath String argument in DexClassLoader");
            FreeMethodInfo(jvmti, class_sig, mname, msig);
            return;
        }

        const char* dex_path = jni->GetStringUTFChars((jstring)dex_path_obj, nullptr);
        if (!dex_path) {
            SendError("dex_dump: GetStringUTFChars failed for dexPath");
            jni->DeleteLocalRef(dex_path_obj);
            FreeMethodInfo(jvmti, class_sig, mname, msig);
            return;
        }

        ALOGI("[DEX] DexClassLoader dexPath: %s", dex_path);

        // Path may contain ':' separators for multiple DEX files
        char path_copy[2048];
        strncpy(path_copy, dex_path, sizeof(path_copy) - 1);
        path_copy[sizeof(path_copy) - 1] = '\0';
        jni->ReleaseStringUTFChars((jstring)dex_path_obj, dex_path);
        jni->DeleteLocalRef(dex_path_obj);

        char* saveptr = nullptr;
        char* token = strtok_r(path_copy, ":", &saveptr);
        while (token) {
            // Trim whitespace
            while (*token == ' ') token++;
            if (*token == '\0') { token = strtok_r(nullptr, ":", &saveptr); continue; }

            ALOGI("[DEX] Reading DEX from: %s", token);
            FILE* f = fopen(token, "rb");
            if (!f) {
                ALOGW("[DEX] Cannot open '%s': %s", token, strerror(errno));
                SendError("dex_dump: cannot open '%s': %s", token, strerror(errno));
                token = strtok_r(nullptr, ":", &saveptr);
                continue;
            }

            fseek(f, 0, SEEK_END);
            long file_size = ftell(f);
            fseek(f, 0, SEEK_SET);

            if (file_size > 0 && file_size <= kMaxDexFileSize) {
                unsigned char* data = (unsigned char*)malloc(file_size);
                if (data) {
                    size_t nread = fread(data, 1, file_size, f);
                    if ((long)nread == file_size) {
                        SendDexLoaded("file", token, data, (int)file_size);
                    } else {
                        SendError("dex_dump: read %zu of %ld bytes from '%s'", nread, file_size, token);
                    }
                    free(data);
                } else {
                    SendError("dex_dump: malloc(%ld) failed", file_size);
                }
            } else {
                SendError("dex_dump: '%s' invalid size (%ld)", token, file_size);
            }
            fclose(f);

            token = strtok_r(nullptr, ":", &saveptr);
        }
    }

    FreeMethodInfo(jvmti, class_sig, mname, msig);
}

// ---------------------------------------------------------------------------
// Milestone 2+3: DebuggerCommandLoop — called on the app thread at breakpoint/step
// Blocks until continue/step command is received.
// ---------------------------------------------------------------------------

void DebuggerCommandLoop(jvmtiEnv* jvmti, JNIEnv* jni, jthread thread,
                         jmethodID method, jlocation location, int bp_id) {
    // Only one thread at a time in the command loop. If another thread hits a
    // breakpoint or step while we are already suspended (e.g. two bp-crypto
    // breakpoints firing concurrently), auto-continue it silently so its
    // command is not stolen from the queue by the wrong thread.
    bool expected = false;
    if (!g_dbg.thread_suspended.compare_exchange_strong(expected, true)) {
        ALOGW("[DBG] Concurrent bp/step on second thread — auto-continuing");
        return;
    }

    // Send hit event
    {
        char* class_sig = nullptr;
        char* mname = nullptr;
        char* msig = nullptr;
        GetMethodInfo(jvmti, method, &class_sig, &mname, &msig);
        int line = LocationToLine(jvmti, method, location);

        JsonBuf jb;
        json_start(&jb);
        if (bp_id >= 0) {
            json_add_string(&jb, "type", "bp_hit");
            json_add_int(&jb, "bp_id", bp_id);
        } else {
            json_add_string(&jb, "type", "step_hit");
        }
        json_add_string(&jb, "class", class_sig ? class_sig : "?");
        json_add_string(&jb, "method", mname ? mname : "?");
        json_add_string(&jb, "sig", msig ? msig : "?");
        json_add_long(&jb, "location", (long long)location);
        json_add_int(&jb, "line", line);
        json_end(&jb);
        SendToClient(jb.buf);

        FreeMethodInfo(jvmti, class_sig, mname, msig);
    }

    // Block in command loop
    while (g_dbg.running) {
        DebuggerCommand dcmd;
        dcmd.cmd[0] = '\0';

        // Wait for a command
        pthread_mutex_lock(&g_dbg.queue_mutex);
        while (g_dbg.cmd_queue.empty() && g_dbg.running && g_dbg.client_fd >= 0) {
            pthread_cond_wait(&g_dbg.queue_cond, &g_dbg.queue_mutex);
        }

        // Check if we should bail (client disconnected or shutting down)
        if (!g_dbg.running || (g_dbg.cmd_queue.empty() && g_dbg.client_fd < 0)) {
            pthread_mutex_unlock(&g_dbg.queue_mutex);
            ALOGI("[DBG] Command loop exiting (disconnected or shutdown)");
            break;
        }

        if (!g_dbg.cmd_queue.empty()) {
            dcmd = g_dbg.cmd_queue.front();
            g_dbg.cmd_queue.erase(g_dbg.cmd_queue.begin());
        }
        pthread_mutex_unlock(&g_dbg.queue_mutex);

        if (dcmd.cmd[0] == '\0') continue;

        ALOGI("[DBG] Suspended cmd: %s", dcmd.cmd);

        if (strcmp(dcmd.cmd, "continue") == 0) {
            JsonBuf jb;
            json_start(&jb);
            json_add_string(&jb, "type", "resumed");
            json_end(&jb);
            SendToClient(jb.buf);
            break;

        } else if (strcmp(dcmd.cmd, "locals") == 0) {
            CmdLocals(jvmti, jni, thread, method, location);

        } else if (strcmp(dcmd.cmd, "regs") == 0) {
            CmdRegs(jvmti, jni, thread, method);

        } else if (strcmp(dcmd.cmd, "set_local") == 0) {
            int slot = 0;
            long long value = 0;
            char type_hint[4] = "I";
            json_get_int(dcmd.raw, "slot", &slot);
            json_get_long(dcmd.raw, "value", &value);
            json_get_string(dcmd.raw, "type_hint", type_hint, sizeof(type_hint));
            jvmtiError err;
            if (type_hint[0] == 'J') {
                err = jvmti->SetLocalLong(thread, 0, slot, (jlong)value);
                if (err != JVMTI_ERROR_NONE)
                    SendError("SetLocalLong failed (err=%d, slot=%d)", err, slot);
            } else if (type_hint[0] == 'F') {
                float fval;
                memcpy(&fval, &value, sizeof(float));
                err = jvmti->SetLocalFloat(thread, 0, slot, fval);
                if (err != JVMTI_ERROR_NONE)
                    SendError("SetLocalFloat failed (err=%d, slot=%d)", err, slot);
            } else if (type_hint[0] == 'D') {
                double dval;
                memcpy(&dval, &value, sizeof(double));
                err = jvmti->SetLocalDouble(thread, 0, slot, dval);
                if (err != JVMTI_ERROR_NONE)
                    SendError("SetLocalDouble failed (err=%d, slot=%d)", err, slot);
            } else {
                err = jvmti->SetLocalInt(thread, 0, slot, (jint)value);
                if (err != JVMTI_ERROR_NONE)
                    SendError("SetLocalInt failed (err=%d, slot=%d)", err, slot);
            }

        } else if (strcmp(dcmd.cmd, "stack") == 0) {
            CmdStack(jvmti, jni, thread);

        } else if (strcmp(dcmd.cmd, "inspect") == 0) {
            CmdInspect(jvmti, jni, thread, dcmd.raw);

        } else if (strcmp(dcmd.cmd, "eval") == 0) {
            CmdEval(jvmti, jni, thread, dcmd.raw);

        } else if (strcmp(dcmd.cmd, "hexdump") == 0) {
            CmdHexdump(jvmti, jni, thread, dcmd.raw);

        } else if (strcmp(dcmd.cmd, "dex_dump") == 0) {
            CmdDexDump(jvmti, jni, thread, method, location);

        } else if (strcmp(dcmd.cmd, "ssl_get_tm_classes") == 0) {
            CmdSslGetTmClasses(jvmti, jni, thread, method);

        } else if (strcmp(dcmd.cmd, "step_into") == 0) {
            if (!g_dbg.cap_single_step) {
                SendError("Single-step not available on this device/Android version");
                continue;  // stay in command loop, don't break
            }
            g_dbg.step_mode = STEP_INTO;
            SetStepThread(jni, thread);
            // Enable globally (NULL) to force ART full deoptimization — ensures
            // single-step fires inside called methods, not just the current frame.
            jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_SINGLE_STEP, nullptr);
            JsonBuf jb;
            json_start(&jb);
            json_add_string(&jb, "type", "stepping");
            json_add_string(&jb, "mode", "into");
            json_end(&jb);
            SendToClient(jb.buf);
            break;

        } else if (strcmp(dcmd.cmd, "step_over") == 0) {
            if (!g_dbg.cap_single_step) {
                SendError("Single-step not available on this device/Android version");
                continue;
            }
            g_dbg.step_mode = STEP_OVER;
            SetStepThread(jni, thread);
            jint fc = 0;
            jvmti->GetFrameCount(thread, &fc);
            g_dbg.step_target_depth = fc;
            jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_SINGLE_STEP, nullptr);
            JsonBuf jb;
            json_start(&jb);
            json_add_string(&jb, "type", "stepping");
            json_add_string(&jb, "mode", "over");
            json_end(&jb);
            SendToClient(jb.buf);
            break;

        } else if (strcmp(dcmd.cmd, "step_out") == 0) {
            if (!g_dbg.cap_single_step) {
                SendError("Single-step not available on this device/Android version");
                continue;
            }
            jint fc = 0;
            jvmti->GetFrameCount(thread, &fc);
            if (fc <= 1) {
                SendError("step_out: already at bottom frame (no caller to return to)");
                continue;
            }
            g_dbg.step_mode = STEP_OUT;
            SetStepThread(jni, thread);
            g_dbg.step_target_depth = fc - 1;
            jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_SINGLE_STEP, nullptr);
            JsonBuf jb;
            json_start(&jb);
            json_add_string(&jb, "type", "stepping");
            json_add_string(&jb, "mode", "out");
            json_end(&jb);
            SendToClient(jb.buf);
            break;

        } else if (strcmp(dcmd.cmd, "step_out2") == 0) {
            if (!g_dbg.cap_frame_pop) {
                SendError("step_out2: can_generate_frame_pop_events not available");
                continue;
            }
            jint fc = 0;
            jvmti->GetFrameCount(thread, &fc);
            if (fc <= 1) {
                SendError("step_out2: already at bottom frame (no caller to return to)");
                continue;
            }
            SetStepThread(jni, thread);
            jvmti->NotifyFramePop(thread, 0);
            jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_FRAME_POP, thread);
            JsonBuf jb;
            json_start(&jb);
            json_add_string(&jb, "type", "stepping");
            json_add_string(&jb, "mode", "out2");
            json_end(&jb);
            SendToClient(jb.buf);
            break;

        } else if (strcmp(dcmd.cmd, "force_return") == 0) {
            if (!g_dbg.cap_force_early_return) {
                SendError("ForceEarlyReturn not available on this device");
                continue;
            }
            int ret_value = 0;
            json_get_int(dcmd.raw, "return_value", &ret_value);

            // Auto-detect method return type from signature to pick the
            // correct ForceEarlyReturn* variant (avoids TYPE_MISMATCH err=34)
            char* msig = nullptr;
            jvmti->GetMethodName(method, nullptr, &msig, nullptr);
            char ret_char = 'V';  // fallback: void
            if (msig) {
                const char* cp = strchr(msig, ')');
                if (cp && *(cp + 1)) ret_char = *(cp + 1);
                jvmti->Deallocate(reinterpret_cast<unsigned char*>(msig));
            }

            jvmtiError ferr;
            switch (ret_char) {
                case 'V':
                    ferr = jvmti->ForceEarlyReturnVoid(thread);
                    break;
                case 'Z': case 'B': case 'C': case 'S': case 'I':
                    ferr = jvmti->ForceEarlyReturnInt(thread, (jint)ret_value);
                    break;
                case 'J':
                    ferr = jvmti->ForceEarlyReturnLong(thread, (jlong)ret_value);
                    break;
                case 'F':
                    ferr = jvmti->ForceEarlyReturnFloat(thread, (jfloat)ret_value);
                    break;
                case 'D':
                    ferr = jvmti->ForceEarlyReturnDouble(thread, (jdouble)ret_value);
                    break;
                case 'L': case '[':
                    ferr = jvmti->ForceEarlyReturnObject(thread, nullptr);
                    break;
                default:
                    SendError("force_return: unexpected return type '%c'", ret_char);
                    continue;
            }

            if (ferr != JVMTI_ERROR_NONE) {
                SendError("ForceEarlyReturn failed (err=%d, retType=%c)", ferr, ret_char);
                continue;
            }

            ALOGI("[DBG] ForceEarlyReturn: type=%c value=%d", ret_char, ret_value);

            // Single-step so execution pauses at the caller's next instruction
            if (g_dbg.cap_single_step) {
                g_dbg.step_mode = STEP_INTO;
                SetStepThread(jni, thread);
                jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_SINGLE_STEP, nullptr);
                JsonBuf jb;
                json_start(&jb);
                json_add_string(&jb, "type", "stepping");
                json_add_string(&jb, "mode", "into");
                json_end(&jb);
                SendToClient(jb.buf);
            } else {
                JsonBuf jb;
                json_start(&jb);
                json_add_string(&jb, "type", "resumed");
                json_end(&jb);
                SendToClient(jb.buf);
            }
            break;

        } else if (strcmp(dcmd.cmd, "dis") == 0) {
            if (!g_dbg.cap_bytecodes) {
                SendError("GetBytecodes not available on this device/Android version");
            } else {
                // Check if a specific class/method was requested
                char req_class[256] = {0};
                char req_method[128] = {0};
                char req_sig[256] = {0};
                json_get_string(dcmd.raw, "class", req_class, sizeof(req_class));
                json_get_string(dcmd.raw, "method", req_method, sizeof(req_method));
                json_get_string(dcmd.raw, "sig", req_sig, sizeof(req_sig));

                jmethodID target_method = method;  // default: current frame
                bool is_current = true;

                // If class/method specified AND different from current, look it up
                if (req_class[0] && req_method[0]) {
                    char* cur_class = nullptr;
                    char* cur_mname = nullptr;
                    char* cur_msig = nullptr;
                    GetMethodInfo(jvmti, method, &cur_class, &cur_mname, &cur_msig);
                    bool same = cur_class && cur_mname &&
                                strcmp(cur_class, req_class) == 0 &&
                                strcmp(cur_mname, req_method) == 0;
                    FreeMethodInfo(jvmti, cur_class, cur_mname, cur_msig);

                    if (!same) {
                        jclass klass = FindClassBySig(jvmti, jni, req_class);
                        if (klass) {
                            jmethodID mid = FindMethodInClass(jvmti, klass,
                                req_method, req_sig[0] ? req_sig : nullptr);
                            jni->DeleteGlobalRef(klass);
                            if (mid) {
                                target_method = mid;
                                is_current = false;
                            } else {
                                SendError("dis: method '%s' not found in class '%s'",
                                          req_method, req_class);
                                goto dis_done;
                            }
                        } else {
                            SendError("dis: class '%s' not found", req_class);
                            goto dis_done;
                        }
                    }
                }

                {
                    jint bytecode_count = 0;
                    unsigned char* bytecodes = nullptr;
                    jvmtiError err = jvmti->GetBytecodes(target_method,
                                                         &bytecode_count, &bytecodes);
                    if (err == JVMTI_ERROR_NONE && bytecodes) {
                        int b64_len = ((bytecode_count + 2) / 3) * 4 + 1;
                        char* b64 = new char[b64_len];
                        base64_encode(bytecodes, bytecode_count, b64, b64_len);
                        jvmti->Deallocate(bytecodes);

                        // Use requested or actual class/method for response
                        char* class_sig = nullptr;
                        char* mname = nullptr;
                        char* msig = nullptr;
                        GetMethodInfo(jvmti, target_method, &class_sig, &mname, &msig);

                        JsonBuf jb;
                        json_start(&jb);
                        json_add_string(&jb, "type", "dis_result");
                        json_add_string(&jb, "class", class_sig ? class_sig : "?");
                        json_add_string(&jb, "method", mname ? mname : "?");
                        json_add_int(&jb, "bytecode_len", bytecode_count);
                        // Only include current_loc when disassembling the current frame
                        if (is_current) {
                            json_add_long(&jb, "current_loc", (long long)location);
                        }
                        json_add_string(&jb, "bytecodes_b64", b64);
                        json_end(&jb);
                        SendToClient(jb.buf);

                        FreeMethodInfo(jvmti, class_sig, mname, msig);
                        delete[] b64;
                    } else {
                        SendError("GetBytecodes failed (err=%d) — method may be native or abstract", err);
                    }
                }
                dis_done:;
            }

        } else if (strcmp(dcmd.cmd, "redefine_class") == 0) {
            // Dequeue the heap-allocated JSON stored by DispatchCommand
            char* redefine_json = nullptr;
            pthread_mutex_lock(&g_dbg.queue_mutex);
            redefine_json = g_dbg.pending_redefine_json;
            g_dbg.pending_redefine_json = nullptr;
            pthread_mutex_unlock(&g_dbg.queue_mutex);
            if (redefine_json) {
                CmdRedefineClass(jvmti, jni, redefine_json);
                free(redefine_json);
            } else {
                SendError("redefine_class: no pending data (internal error)");
            }

        } else {
            JsonBuf jb;
            json_start(&jb);
            json_add_string(&jb, "type", "error");
            char msg[256];
            snprintf(msg, sizeof(msg), "unknown suspended cmd: %s", dcmd.cmd);
            json_add_string(&jb, "msg", msg);
            json_end(&jb);
            SendToClient(jb.buf);
        }
    }

    g_dbg.thread_suspended = false;
}

// ---------------------------------------------------------------------------
// HandleFramePop — called from OnFramePop callback in agent.cpp (sout2)
// ---------------------------------------------------------------------------

void HandleFramePop(jvmtiEnv* jvmti, JNIEnv* jni, jthread thread,
                    jmethodID method, jboolean was_exception) {
    // Guard: only fire for the thread that issued step_out2
    if (!g_dbg.step_thread || !jni->IsSameObject(thread, g_dbg.step_thread)) return;

    // One-shot: disable per-thread event immediately
    jvmti->SetEventNotificationMode(JVMTI_DISABLE, JVMTI_EVENT_FRAME_POP, thread);

    // Send minimal frame_pop event — method info lookup skipped (unreliable in FramePop)
    JsonBuf jb;
    json_start(&jb);
    json_add_string(&jb, "type", "frame_pop");
    json_add_string(&jb, "class", "");
    json_add_string(&jb, "method", "");
    json_add_string(&jb, "ret_type", "");
    json_add_string(&jb, "ret_value", "");
    json_add_bool(&jb, "was_exception", was_exception);
    json_end(&jb);
    SendToClient(jb.buf);

    // Enable single-step (STEP_INTO) — OnSingleStep fires at caller's next instruction.
    // Same pattern as ForceEarlyReturn: do NOT call DebuggerCommandLoop from FramePop.
    if (g_dbg.cap_single_step) {
        g_dbg.step_mode = STEP_INTO;
        jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_SINGLE_STEP, nullptr);
    }
}

// ---------------------------------------------------------------------------
// Milestone 3: ShouldStopStepping — called from OnSingleStep
// ---------------------------------------------------------------------------

bool ShouldStopStepping(jvmtiEnv* jvmti, JNIEnv* jni, jthread thread,
                        jmethodID method, jlocation location) {
    // No step in progress - disable stale event and bail
    if (g_dbg.step_mode == STEP_NONE || !g_dbg.step_thread) {
        jvmti->SetEventNotificationMode(JVMTI_DISABLE, JVMTI_EVENT_SINGLE_STEP, nullptr);
        g_dbg.step_mode = STEP_NONE;
        ClearStepThread(jni);
        return false;
    }

    // Global single-step fires for all threads - only process our step thread.
    // Do NOT probe step_thread with GetThreadInfo here: ART frees the internal
    // C++ Thread* when the thread terminates, even while we hold a global ref
    // to the Java peer, causing GetThreadInfo to crash (SIGSEGV at +44).
    // Thread termination cleanup is handled safely in HandleStepThreadEnd.
    if (!jni->IsSameObject(thread, g_dbg.step_thread)) {
        return false;
    }

    if (g_dbg.step_mode == STEP_INTO) {
        // Always stop on next bytecode
        jvmti->SetEventNotificationMode(JVMTI_DISABLE, JVMTI_EVENT_SINGLE_STEP, nullptr);
        g_dbg.step_mode = STEP_NONE;
        ClearStepThread(jni);
        return true;
    }

    if (g_dbg.step_mode == STEP_OVER) {
        jint fc = 0;
        jvmti->GetFrameCount(thread, &fc);
        if (fc <= g_dbg.step_target_depth) {
            jvmti->SetEventNotificationMode(JVMTI_DISABLE, JVMTI_EVENT_SINGLE_STEP, nullptr);
            g_dbg.step_mode = STEP_NONE;
            ClearStepThread(jni);
            return true;
        }
        return false;
    }

    if (g_dbg.step_mode == STEP_OUT) {
        jint fc = 0;
        jvmti->GetFrameCount(thread, &fc);
        if (fc <= g_dbg.step_target_depth) {
            jvmti->SetEventNotificationMode(JVMTI_DISABLE, JVMTI_EVENT_SINGLE_STEP, nullptr);
            g_dbg.step_mode = STEP_NONE;
            ClearStepThread(jni);
            return true;
        }
        return false;
    }

    // Shouldn't get here — disable stepping
    jvmti->SetEventNotificationMode(JVMTI_DISABLE, JVMTI_EVENT_SINGLE_STEP, nullptr);
    g_dbg.step_mode = STEP_NONE;
    ClearStepThread(jni);
    return true;
}

// ---------------------------------------------------------------------------
// HandleStepThreadEnd — called from OnThreadEnd in agent.cpp
// ---------------------------------------------------------------------------

void HandleStepThreadEnd(jvmtiEnv* jvmti, JNIEnv* jni, jthread thread) {
    if (!g_dbg.step_thread) return;
    if (!jni->IsSameObject(thread, g_dbg.step_thread)) return;

    ALOGW("[DBG] Step thread terminated during stepping - cleaning up");
    jvmti->SetEventNotificationMode(JVMTI_DISABLE, JVMTI_EVENT_SINGLE_STEP, nullptr);
    g_dbg.step_mode = STEP_NONE;
    ClearStepThread(jni);

    JsonBuf jb;
    json_start(&jb);
    json_add_string(&jb, "type", "step_thread_end");
    json_end(&jb);
    SendToClient(jb.buf);
}

// ---------------------------------------------------------------------------
// suspend: pause a thread by name, enter debugger command loop on it
// ---------------------------------------------------------------------------

static void CmdSuspend(jvmtiEnv* jvmti, JNIEnv* jni, const char* json) {
    // Note: don't gate on cap_suspend — ART often supports SuspendThread
    // even when can_suspend isn't listed in potential capabilities.
    char thread_name[256] = "main";
    json_get_string(json, "thread", thread_name, sizeof(thread_name));

    if (g_dbg.thread_suspended) {
        JsonBuf jb;
        json_start(&jb);
        json_add_string(&jb, "type", "error");
        json_add_string(&jb, "msg", "a thread is already suspended");
        json_end(&jb);
        SendToClient(jb.buf);
        return;
    }

    // Find the thread by name
    jint thread_count = 0;
    jthread* threads = nullptr;
    if (jvmti->GetAllThreads(&thread_count, &threads) != JVMTI_ERROR_NONE) {
        JsonBuf jb;
        json_start(&jb);
        json_add_string(&jb, "type", "error");
        json_add_string(&jb, "msg", "GetAllThreads failed");
        json_end(&jb);
        SendToClient(jb.buf);
        return;
    }

    jthread target = nullptr;
    for (int i = 0; i < thread_count; i++) {
        jvmtiThreadInfo info;
        memset(&info, 0, sizeof(info));
        if (jvmti->GetThreadInfo(threads[i], &info) == JVMTI_ERROR_NONE) {
            bool match = (info.name && strcmp(info.name, thread_name) == 0);
            if (info.name) jvmti->Deallocate(reinterpret_cast<unsigned char*>(info.name));
            if (match) {
                target = threads[i];
                // Don't delete this ref yet
                continue;
            }
        }
        jni->DeleteLocalRef(threads[i]);
    }
    jvmti->Deallocate(reinterpret_cast<unsigned char*>(threads));

    if (!target) {
        JsonBuf jb;
        json_start(&jb);
        json_add_string(&jb, "type", "error");
        char msg[256];
        snprintf(msg, sizeof(msg), "thread '%s' not found", thread_name);
        json_add_string(&jb, "msg", msg);
        json_end(&jb);
        SendToClient(jb.buf);
        return;
    }

    // Suspend the thread
    jvmtiError err = jvmti->SuspendThread(target);
    if (err != JVMTI_ERROR_NONE) {
        jni->DeleteLocalRef(target);
        JsonBuf jb;
        json_start(&jb);
        json_add_string(&jb, "type", "error");
        char msg[128];
        snprintf(msg, sizeof(msg), "SuspendThread failed: %d", err);
        json_add_string(&jb, "msg", msg);
        json_end(&jb);
        SendToClient(jb.buf);
        return;
    }

    // Get top frame info
    jvmtiFrameInfo frame;
    jint frame_count = 0;
    err = jvmti->GetStackTrace(target, 0, 1, &frame, &frame_count);
    if (err != JVMTI_ERROR_NONE || frame_count == 0) {
        jvmti->ResumeThread(target);
        jni->DeleteLocalRef(target);
        JsonBuf jb;
        json_start(&jb);
        json_add_string(&jb, "type", "error");
        json_add_string(&jb, "msg", "suspended but no Java frames");
        json_end(&jb);
        SendToClient(jb.buf);
        return;
    }

    ALOGI("[DBG] Suspended thread '%s'", thread_name);

    // Store suspended thread and enter command loop on the socket thread.
    // We handle commands here since the target thread is externally suspended
    // (not blocked inside a callback like breakpoint). We'll process commands
    // on the socket thread, then ResumeThread when done.
    g_dbg.thread_suspended = true;

    // Send suspended event
    {
        char* class_sig = nullptr;
        char* mname = nullptr;
        char* msig = nullptr;
        GetMethodInfo(jvmti, frame.method, &class_sig, &mname, &msig);
        int line = LocationToLine(jvmti, frame.method, frame.location);

        JsonBuf jb;
        json_start(&jb);
        json_add_string(&jb, "type", "suspended");
        json_add_string(&jb, "thread", thread_name);
        json_add_string(&jb, "class", class_sig ? class_sig : "?");
        json_add_string(&jb, "method", mname ? mname : "?");
        json_add_string(&jb, "sig", msig ? msig : "?");
        json_add_long(&jb, "location", (long long)frame.location);
        json_add_int(&jb, "line", line);
        json_end(&jb);
        SendToClient(jb.buf);

        FreeMethodInfo(jvmti, class_sig, mname, msig);
    }

    // Inline command loop (runs on socket thread, target thread is JVMTI-suspended)
    while (g_dbg.running && g_dbg.client_fd >= 0) {
        // Read next line directly from socket (we're on the socket thread)
        // We need to temporarily read commands synchronously
        char line_buf[4096];
        int line_pos = 0;
        bool got_line = false;

        while (g_dbg.running && g_dbg.client_fd >= 0) {
            char c;
            int n = recv(g_dbg.client_fd, &c, 1, 0);
            if (n <= 0) break;
            if (c == '\n') { got_line = true; break; }
            if (line_pos < (int)sizeof(line_buf) - 1)
                line_buf[line_pos++] = c;
        }
        line_buf[line_pos] = '\0';

        if (!got_line) {
            ALOGI("[DBG] Suspend loop: client disconnected");
            break;
        }

        char cmd[64] = "";
        json_get_string(line_buf, "cmd", cmd, sizeof(cmd));
        ALOGI("[DBG] Suspend cmd: %s", cmd);

        if (strcmp(cmd, "continue") == 0 || strcmp(cmd, "c") == 0) {
            jvmti->ResumeThread(target);
            JsonBuf jb;
            json_start(&jb);
            json_add_string(&jb, "type", "resumed");
            json_end(&jb);
            SendToClient(jb.buf);
            break;

        } else if (strcmp(cmd, "locals") == 0) {
            CmdLocals(jvmti, jni, target, frame.method, frame.location);

        } else if (strcmp(cmd, "regs") == 0) {
            CmdRegs(jvmti, jni, target, frame.method);

        } else if (strcmp(cmd, "stack") == 0) {
            CmdStack(jvmti, jni, target);

        } else if (strcmp(cmd, "inspect") == 0) {
            CmdInspect(jvmti, jni, target, line_buf);

        } else if (strcmp(cmd, "eval") == 0) {
            CmdEval(jvmti, jni, target, line_buf);

        } else if (strcmp(cmd, "dis") == 0) {
            if (!g_dbg.cap_bytecodes) {
                SendError("GetBytecodes not available on this device/Android version");
            } else {
                // Check if a specific class/method was requested
                char req_class[256] = {0};
                char req_method[128] = {0};
                char req_sig[256] = {0};
                json_get_string(line_buf, "class", req_class, sizeof(req_class));
                json_get_string(line_buf, "method", req_method, sizeof(req_method));
                json_get_string(line_buf, "sig", req_sig, sizeof(req_sig));

                jmethodID dis_method = frame.method;
                bool dis_is_current = true;

                if (req_class[0] && req_method[0]) {
                    char* cur_cs = nullptr; char* cur_mn = nullptr; char* cur_ms = nullptr;
                    GetMethodInfo(jvmti, frame.method, &cur_cs, &cur_mn, &cur_ms);
                    bool same = cur_cs && cur_mn &&
                                strcmp(cur_cs, req_class) == 0 &&
                                strcmp(cur_mn, req_method) == 0;
                    FreeMethodInfo(jvmti, cur_cs, cur_mn, cur_ms);

                    if (!same) {
                        jclass klass = FindClassBySig(jvmti, jni, req_class);
                        if (klass) {
                            jmethodID mid = FindMethodInClass(jvmti, klass,
                                req_method, req_sig[0] ? req_sig : nullptr);
                            jni->DeleteGlobalRef(klass);
                            if (mid) {
                                dis_method = mid;
                                dis_is_current = false;
                            } else {
                                SendError("dis: method '%s' not found in class '%s'",
                                          req_method, req_class);
                                continue;
                            }
                        } else {
                            SendError("dis: class '%s' not found", req_class);
                            continue;
                        }
                    }
                }

                jint bytecode_count = 0;
                unsigned char* bytecodes = nullptr;
                jvmtiError berr = jvmti->GetBytecodes(dis_method, &bytecode_count, &bytecodes);
                if (berr == JVMTI_ERROR_NONE && bytecodes) {
                    int b64_len = ((bytecode_count + 2) / 3) * 4 + 1;
                    char* b64 = new char[b64_len];
                    base64_encode(bytecodes, bytecode_count, b64, b64_len);
                    jvmti->Deallocate(bytecodes);

                    char* cs = nullptr; char* mn = nullptr; char* ms = nullptr;
                    GetMethodInfo(jvmti, dis_method, &cs, &mn, &ms);

                    JsonBuf jb;
                    json_start(&jb);
                    json_add_string(&jb, "type", "dis_result");
                    json_add_string(&jb, "class", cs ? cs : "?");
                    json_add_string(&jb, "method", mn ? mn : "?");
                    json_add_int(&jb, "bytecode_len", bytecode_count);
                    if (dis_is_current) {
                        json_add_long(&jb, "current_loc", (long long)frame.location);
                    }
                    json_add_string(&jb, "bytecodes_b64", b64);
                    json_end(&jb);
                    SendToClient(jb.buf);

                    FreeMethodInfo(jvmti, cs, mn, ms);
                    delete[] b64;
                } else {
                    SendError("GetBytecodes failed (err=%d) — method may be native or abstract", berr);
                }
            }

        } else if (strcmp(cmd, "step_into") == 0) {
            if (!g_dbg.cap_single_step) {
                SendError("Single-step not available on this device/Android version");
                continue;
            }
            g_dbg.step_mode = STEP_INTO;
            SetStepThread(jni, target);
            jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_SINGLE_STEP, nullptr);
            jvmti->ResumeThread(target);
            JsonBuf jb;
            json_start(&jb);
            json_add_string(&jb, "type", "stepping");
            json_add_string(&jb, "mode", "into");
            json_end(&jb);
            SendToClient(jb.buf);
            break;

        } else if (strcmp(cmd, "step_over") == 0) {
            if (!g_dbg.cap_single_step) {
                SendError("Single-step not available on this device/Android version");
                continue;
            }
            g_dbg.step_mode = STEP_OVER;
            SetStepThread(jni, target);
            jint fc = 0;
            jvmti->GetFrameCount(target, &fc);
            g_dbg.step_target_depth = fc;
            jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_SINGLE_STEP, nullptr);
            jvmti->ResumeThread(target);
            JsonBuf jb;
            json_start(&jb);
            json_add_string(&jb, "type", "stepping");
            json_add_string(&jb, "mode", "over");
            json_end(&jb);
            SendToClient(jb.buf);
            break;

        } else if (strcmp(cmd, "step_out") == 0) {
            if (!g_dbg.cap_single_step) {
                SendError("Single-step not available on this device/Android version");
                continue;
            }
            jint fc = 0;
            jvmti->GetFrameCount(target, &fc);
            if (fc <= 1) {
                SendError("step_out: already at bottom frame (no caller to return to)");
                continue;
            }
            g_dbg.step_mode = STEP_OUT;
            SetStepThread(jni, target);
            g_dbg.step_target_depth = fc - 1;
            jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_SINGLE_STEP, nullptr);
            jvmti->ResumeThread(target);
            JsonBuf jb;
            json_start(&jb);
            json_add_string(&jb, "type", "stepping");
            json_add_string(&jb, "mode", "out");
            json_end(&jb);
            SendToClient(jb.buf);
            break;

        } else if (strcmp(cmd, "step_out2") == 0) {
            if (!g_dbg.cap_frame_pop) {
                SendError("step_out2: can_generate_frame_pop_events not available");
                continue;
            }
            jint fc = 0;
            jvmti->GetFrameCount(target, &fc);
            if (fc <= 1) {
                SendError("step_out2: already at bottom frame (no caller to return to)");
                continue;
            }
            SetStepThread(jni, target);
            jvmti->NotifyFramePop(target, 0);
            jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_FRAME_POP, target);
            jvmti->ResumeThread(target);
            JsonBuf jb;
            json_start(&jb);
            json_add_string(&jb, "type", "stepping");
            json_add_string(&jb, "mode", "out2");
            json_end(&jb);
            SendToClient(jb.buf);
            break;

        } else if (strcmp(cmd, "force_return") == 0) {
            if (!g_dbg.cap_force_early_return) {
                SendError("ForceEarlyReturn not available on this device");
                continue;
            }
            int ret_value = 0;
            json_get_int(line_buf, "return_value", &ret_value);

            // Auto-detect method return type from signature to pick the
            // correct ForceEarlyReturn* variant (avoids TYPE_MISMATCH err=34)
            char* msig = nullptr;
            jvmti->GetMethodName(frame.method, nullptr, &msig, nullptr);
            char ret_char = 'V';
            if (msig) {
                const char* cp = strchr(msig, ')');
                if (cp && *(cp + 1)) ret_char = *(cp + 1);
                jvmti->Deallocate(reinterpret_cast<unsigned char*>(msig));
            }

            jvmtiError ferr;
            switch (ret_char) {
                case 'V':
                    ferr = jvmti->ForceEarlyReturnVoid(target);
                    break;
                case 'Z': case 'B': case 'C': case 'S': case 'I':
                    ferr = jvmti->ForceEarlyReturnInt(target, (jint)ret_value);
                    break;
                case 'J':
                    ferr = jvmti->ForceEarlyReturnLong(target, (jlong)ret_value);
                    break;
                case 'F':
                    ferr = jvmti->ForceEarlyReturnFloat(target, (jfloat)ret_value);
                    break;
                case 'D':
                    ferr = jvmti->ForceEarlyReturnDouble(target, (jdouble)ret_value);
                    break;
                case 'L': case '[':
                    ferr = jvmti->ForceEarlyReturnObject(target, nullptr);
                    break;
                default:
                    SendError("force_return: unexpected return type '%c'", ret_char);
                    continue;
            }

            if (ferr != JVMTI_ERROR_NONE) {
                SendError("ForceEarlyReturn failed (err=%d, retType=%c)", ferr, ret_char);
                continue;
            }

            ALOGI("[DBG] ForceEarlyReturn: type=%c value=%d", ret_char, ret_value);

            if (g_dbg.cap_single_step) {
                g_dbg.step_mode = STEP_INTO;
                SetStepThread(jni, target);
                jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_SINGLE_STEP, nullptr);
                jvmti->ResumeThread(target);
                JsonBuf jb;
                json_start(&jb);
                json_add_string(&jb, "type", "stepping");
                json_add_string(&jb, "mode", "into");
                json_end(&jb);
                SendToClient(jb.buf);
            } else {
                jvmti->ResumeThread(target);
                JsonBuf jb;
                json_start(&jb);
                json_add_string(&jb, "type", "resumed");
                json_end(&jb);
                SendToClient(jb.buf);
            }
            break;

        } else {
            // Not a suspend-specific command — try global commands
            // (bp_set, bp_clear, bp_list, cls, methods, fields, threads, heap, etc.)
            DispatchGlobalCommand(jvmti, jni, cmd, line_buf);
        }
    }

    g_dbg.thread_suspended = false;
    jni->DeleteLocalRef(target);
}

// ---------------------------------------------------------------------------
// JNI monitoring — jni_monitor_start / stop / redirect
// ---------------------------------------------------------------------------

// Resolve an arbitrary native address to a library basename + offset within
// that library's loaded region.  Uses /proc/self/maps.
// Returns false if the address could not be mapped.
static bool ResolveNativeAddr(void* addr, char* lib_out, size_t lib_sz, uintptr_t* offset_out) {
    FILE* f = fopen("/proc/self/maps", "r");
    if (!f) return false;

    uintptr_t target = (uintptr_t)addr;
    char line[512];
    bool found = false;

    while (fgets(line, sizeof(line), f)) {
        uintptr_t start = 0, end = 0;
        char perms[8] = "", path[256] = "";
        unsigned long long file_offset = 0;
        int dm = 0, dn = 0;
        unsigned long inode = 0;
        // Format: start-end perms offset dev inode [path]
        sscanf(line, "%lx-%lx %4s %llx %x:%x %lu %255s",
               &start, &end, perms, &file_offset, &dm, &dn, &inode, path);
        if (target >= start && target < end) {
            const char* base = strrchr(path, '/');
            base = (base && base[1]) ? base + 1 : path;
            strncpy(lib_out, base[0] ? base : "[anon]", lib_sz - 1);
            lib_out[lib_sz - 1] = '\0';
            *offset_out = target - start;
            found = true;
            break;
        }
    }
    fclose(f);
    return found;
}

static void SendJniRegisterNative(const char* class_sig, const char* method_name,
                                   const char* method_sig, uint64_t native_addr,
                                   const char* lib_name, uint64_t lib_offset) {
    JsonBuf jb;
    json_start(&jb);
    json_add_string(&jb, "type", "jni_register_native");
    json_add_string(&jb, "class_sig", class_sig);
    json_add_string(&jb, "method_name", method_name);
    json_add_string(&jb, "method_sig", method_sig);
    json_add_long(&jb, "native_addr", (long long)native_addr);
    json_add_string(&jb, "lib_name", lib_name);
    json_add_long(&jb, "lib_offset", (long long)lib_offset);
    json_end(&jb);
    SendToClient(jb.buf);
}

// ---------------------------------------------------------------------------
// JNI stub functions — installed as native method replacements.
// Each stub matches JNI calling convention (JNIEnv*, jobject, ...) and returns
// a zeroed/null/false value appropriate for the method's return type.
// The "true" variants are used when action == "true" for boolean methods.
// ---------------------------------------------------------------------------
static jboolean jni_stub_bool_false(JNIEnv*, jobject, ...) { return JNI_FALSE; }
static jboolean jni_stub_bool_true (JNIEnv*, jobject, ...) { return JNI_TRUE;  }
static jint     jni_stub_int_0     (JNIEnv*, jobject, ...) { return 0; }
static jlong    jni_stub_long_0    (JNIEnv*, jobject, ...) { return 0L; }
static jfloat   jni_stub_float_0   (JNIEnv*, jobject, ...) { return 0.0f; }
static jdouble  jni_stub_double_0  (JNIEnv*, jobject, ...) { return 0.0; }
static jobject  jni_stub_null      (JNIEnv*, jobject, ...) { return nullptr; }
static void     jni_stub_void      (JNIEnv*, jobject, ...) {}

// Select stub based on JNI return type char (char after ')' in method sig)
// and action string ("block", "true", "spoof").
static void* SelectJniStub(char ret_char, const char* action, int64_t /*spoof_value*/) {
    bool want_true = (strcmp(action, "true") == 0);
    switch (ret_char) {
        case 'Z': return (void*)(want_true ? jni_stub_bool_true : jni_stub_bool_false);
        case 'B': case 'C': case 'S': case 'I': return (void*)jni_stub_int_0;
        case 'J': return (void*)jni_stub_long_0;
        case 'F': return (void*)jni_stub_float_0;
        case 'D': return (void*)jni_stub_double_0;
        case 'V': return (void*)jni_stub_void;
        default:  return (void*)jni_stub_null; // L, [, or unknown -> null object
    }
}

// ---------------------------------------------------------------------------
// Hook for JNIEnv::RegisterNatives
// Intercepts calls from any thread whose JNIEnv has been patched.
// ---------------------------------------------------------------------------
static jint Hook_RegisterNatives(JNIEnv* env, jclass clazz,
                                  const JNINativeMethod* methods, jint nMethods) {
    // Resolve class signature via JVMTI (doesn't go through the JNI vtable)
    char* class_sig = nullptr;
    g_dbg.jvmti->GetClassSignature(clazz, &class_sig, nullptr);

    for (int i = 0; i < nMethods; i++) {
        char lib_name[256] = "[unknown]";
        uintptr_t lib_offset = 0;
        ResolveNativeAddr(methods[i].fnPtr, lib_name, sizeof(lib_name), &lib_offset);

        SendJniRegisterNative(
            class_sig ? class_sig : "?",
            methods[i].name ? methods[i].name : "?",
            methods[i].signature ? methods[i].signature : "?",
            (uint64_t)(uintptr_t)methods[i].fnPtr,
            lib_name, (uint64_t)lib_offset);

        // Store original pointer for any matching redirect entry
        if (class_sig && methods[i].name && methods[i].signature) {
            std::string key = std::string(class_sig) + ":"
                            + methods[i].name + ":"
                            + methods[i].signature;
            pthread_mutex_lock(&g_dbg.jni_redirect_mutex);
            auto it = g_dbg.jni_redirects.find(key);
            if (it != g_dbg.jni_redirects.end() && it->second.original_fnptr == nullptr) {
                it->second.original_fnptr = methods[i].fnPtr;
            }
            pthread_mutex_unlock(&g_dbg.jni_redirect_mutex);
        }
    }

    g_dbg.jni_capture_count.fetch_add(nMethods);
    if (class_sig) g_dbg.jvmti->Deallocate((unsigned char*)class_sig);

    // Call the real RegisterNatives via saved original table
    return g_dbg.jni_original_table->RegisterNatives(env, clazz, methods, nMethods);
}

void PatchJniEnvForMonitor(JNIEnv* env) {
    if (!env) return;
    // Only patch if this env still points to the original table (idempotent)
    if (env->functions == &g_dbg.jni_hooked_table) return;
    if (env->functions != g_dbg.jni_original_table) return;
    env->functions = &g_dbg.jni_hooked_table;
}

void HandleThreadStart(jvmtiEnv* /*jvmti*/, JNIEnv* jni, jthread /*thread*/) {
    if (g_dbg.jni_monitoring.load() && jni) {
        PatchJniEnvForMonitor(jni);
    }
}

static void CmdJniMonitorStart(jvmtiEnv* /*jvmti*/, JNIEnv* jni, const char* /*json*/) {
    if (g_dbg.jni_monitoring.load()) {
        SendError("jni_monitor already active");
        return;
    }
    if (!jni) {
        SendError("jni_monitor: no JNIEnv available");
        return;
    }

    // Save original vtable and build hooked copy
    g_dbg.jni_original_table = jni->functions;
    memcpy(&g_dbg.jni_hooked_table, g_dbg.jni_original_table, sizeof(JNINativeInterface));
    g_dbg.jni_hooked_table.RegisterNatives = Hook_RegisterNatives;
    g_dbg.jni_capture_count.store(0);
    g_dbg.jni_monitoring.store(true);

    // Patch this thread's env immediately; ThreadStart callback handles future threads
    PatchJniEnvForMonitor(jni);

    ALOGI("[DBG] JNI monitor started");
    JsonBuf jb;
    json_start(&jb);
    json_add_string(&jb, "type", "jni_monitor_started");
    json_end(&jb);
    SendToClient(jb.buf);
}

static void CmdJniMonitorStop(jvmtiEnv* /*jvmti*/, JNIEnv* jni, const char* /*json*/) {
    if (!g_dbg.jni_monitoring.load()) {
        SendError("jni_monitor not active");
        return;
    }
    g_dbg.jni_monitoring.store(false);

    // Restore this thread's env; other threads will keep the hook until their
    // next patched vtable lookup, which is harmless (we just stop capturing).
    if (jni && jni->functions == &g_dbg.jni_hooked_table) {
        jni->functions = g_dbg.jni_original_table;
    }

    int total = g_dbg.jni_capture_count.load();
    ALOGI("[DBG] JNI monitor stopped (%d captures)", total);
    JsonBuf jb;
    json_start(&jb);
    json_add_string(&jb, "type", "jni_monitor_stopped");
    json_add_int(&jb, "count", total);
    json_end(&jb);
    SendToClient(jb.buf);
}

static void CmdJniRedirectSet(jvmtiEnv* jvmti, JNIEnv* jni, const char* json) {
    char class_sig[256]   = {0};
    char method_name[128] = {0};
    char method_sig[256]  = {0};
    char action[32]       = "block";
    int64_t spoof_value   = 0;

    if (!json_get_string(json, "class_sig",   class_sig,   sizeof(class_sig))  ||
        !json_get_string(json, "method_name", method_name, sizeof(method_name))||
        !json_get_string(json, "method_sig",  method_sig,  sizeof(method_sig))) {
        SendError("jni_redirect_set: missing class_sig/method_name/method_sig");
        return;
    }
    json_get_string(json, "action", action, sizeof(action));
    // spoof_value: optional int64 (parse manually if present)
    {
        const char* p = strstr(json, "\"spoof_value\"");
        if (p) { p = strchr(p, ':'); if (p) spoof_value = (int64_t)strtoll(p + 1, nullptr, 10); }
    }

    jclass klass = FindClassBySig(jvmti, jni, class_sig);
    if (!klass) {
        SendError("jni_redirect_set: class not loaded: %s", class_sig);
        return;
    }

    // Determine return type from method signature (char after ')')
    const char* ret_ptr = strrchr(method_sig, ')');
    if (!ret_ptr || !ret_ptr[1]) {
        jni->DeleteGlobalRef(klass);
        SendError("jni_redirect_set: bad method_sig %s", method_sig);
        return;
    }
    char ret_char = ret_ptr[1];
    void* stub = SelectJniStub(ret_char, action, spoof_value);

    // Save original pointer if we have it from monitor captures
    std::string key = std::string(class_sig) + ":" + method_name + ":" + method_sig;
    void* original = nullptr;
    pthread_mutex_lock(&g_dbg.jni_redirect_mutex);
    auto it = g_dbg.jni_redirects.find(key);
    if (it != g_dbg.jni_redirects.end()) {
        original = it->second.original_fnptr;
    }
    pthread_mutex_unlock(&g_dbg.jni_redirect_mutex);

    // Durable string storage for the JNINativeMethod (ART may keep the pointer)
    JniRedirect redir;
    memset(&redir, 0, sizeof(redir));
    redir.original_fnptr = original;
    strncpy(redir.class_sig,   class_sig,   sizeof(redir.class_sig) - 1);
    strncpy(redir.method_name, method_name, sizeof(redir.method_name) - 1);
    strncpy(redir.method_sig,  method_sig,  sizeof(redir.method_sig) - 1);
    strncpy(redir.action,      action,      sizeof(redir.action) - 1);
    redir.spoof_value = spoof_value;

    pthread_mutex_lock(&g_dbg.jni_redirect_mutex);
    g_dbg.jni_redirects[key] = redir;
    JniRedirect& stored = g_dbg.jni_redirects[key];
    pthread_mutex_unlock(&g_dbg.jni_redirect_mutex);

    JNINativeMethod nm;
    nm.name      = stored.method_name;
    nm.signature = stored.method_sig;
    nm.fnPtr     = stub;
    jint err = jni->RegisterNatives(klass, &nm, 1);
    jni->DeleteGlobalRef(klass);

    if (err != 0) {
        SendError("jni_redirect_set: RegisterNatives failed: err=%d", (int)err);
        return;
    }

    ALOGI("[DBG] JNI redirect set: %s.%s%s -> %s", class_sig, method_name, method_sig, action);
    JsonBuf jb;
    json_start(&jb);
    json_add_string(&jb, "type", "jni_redirect_ok");
    json_add_string(&jb, "class_sig",   class_sig);
    json_add_string(&jb, "method_name", method_name);
    json_add_string(&jb, "method_sig",  method_sig);
    json_end(&jb);
    SendToClient(jb.buf);
}

static void CmdJniRedirectClear(jvmtiEnv* jvmti, JNIEnv* jni, const char* json) {
    char class_sig[256]   = {0};
    char method_name[128] = {0};
    char method_sig[256]  = {0};

    if (!json_get_string(json, "class_sig",   class_sig,   sizeof(class_sig))  ||
        !json_get_string(json, "method_name", method_name, sizeof(method_name))||
        !json_get_string(json, "method_sig",  method_sig,  sizeof(method_sig))) {
        SendError("jni_redirect_clear: missing fields");
        return;
    }

    std::string key = std::string(class_sig) + ":" + method_name + ":" + method_sig;
    pthread_mutex_lock(&g_dbg.jni_redirect_mutex);
    auto it = g_dbg.jni_redirects.find(key);
    void* original = (it != g_dbg.jni_redirects.end()) ? it->second.original_fnptr : nullptr;
    if (it != g_dbg.jni_redirects.end()) g_dbg.jni_redirects.erase(it);
    pthread_mutex_unlock(&g_dbg.jni_redirect_mutex);

    if (!original) {
        SendError("jni_redirect_clear: no original pointer saved for %s.%s — was it captured by monitor?",
                  class_sig, method_name);
        return;
    }

    jclass klass = FindClassBySig(jvmti, jni, class_sig);
    if (!klass) {
        SendError("jni_redirect_clear: class not loaded: %s", class_sig);
        return;
    }

    // method_name/method_sig need to persist — use static buffers from the redir struct
    // (already erased from map, but we have local copies)
    static char s_method_name[128];
    static char s_method_sig[256];
    strncpy(s_method_name, method_name, sizeof(s_method_name) - 1);
    strncpy(s_method_sig,  method_sig,  sizeof(s_method_sig) - 1);

    JNINativeMethod nm;
    nm.name      = s_method_name;
    nm.signature = s_method_sig;
    nm.fnPtr     = original;
    jint err = jni->RegisterNatives(klass, &nm, 1);
    jni->DeleteGlobalRef(klass);

    if (err != 0) {
        SendError("jni_redirect_clear: RegisterNatives failed: err=%d", (int)err);
        return;
    }

    ALOGI("[DBG] JNI redirect cleared: %s.%s%s", class_sig, method_name, method_sig);
    JsonBuf jb;
    json_start(&jb);
    json_add_string(&jb, "type", "jni_redirect_cleared");
    json_add_string(&jb, "class_sig",   class_sig);
    json_add_string(&jb, "method_name", method_name);
    json_add_string(&jb, "method_sig",  method_sig);
    json_end(&jb);
    SendToClient(jb.buf);
}

// ---------------------------------------------------------------------------
// Call recording — record_start / record_stop
// ---------------------------------------------------------------------------

static void CmdRecordStart(jvmtiEnv* jvmti, JNIEnv* jni, const char* json) {
    if (g_dbg.recording.load()) {
        SendError("already recording");
        return;
    }

    g_dbg.call_seq.store(0);
    g_dbg.calls_this_second = 0;
    g_dbg.rate_limit_epoch = 0;
    g_dbg.recording.store(true);

    // Enable METHOD_EXIT events for return value capture
    if (g_dbg.cap_method_exit) {
        jvmti->SetEventNotificationMode(JVMTI_ENABLE,
            JVMTI_EVENT_METHOD_EXIT, nullptr);
    }

    ALOGI("[DBG] Call recording started");
    JsonBuf jb;
    json_start(&jb);
    json_add_string(&jb, "type", "record_started");
    json_end(&jb);
    SendToClient(jb.buf);
}

static void CmdRecordStop(jvmtiEnv* jvmti, JNIEnv* jni, const char* json) {
    if (!g_dbg.recording.load()) {
        SendError("not recording");
        return;
    }

    g_dbg.recording.store(false);

    // Disable METHOD_EXIT events
    if (g_dbg.cap_method_exit) {
        jvmti->SetEventNotificationMode(JVMTI_DISABLE,
            JVMTI_EVENT_METHOD_EXIT, nullptr);
    }

    int total = g_dbg.call_seq.load();
    ALOGI("[DBG] Call recording stopped (%d calls)", total);
    JsonBuf jb;
    json_start(&jb);
    json_add_string(&jb, "type", "record_stopped");
    json_add_int(&jb, "total", total);
    json_end(&jb);
    SendToClient(jb.buf);
}

// ---------------------------------------------------------------------------
// redefine_class: replace a class's bytecode at runtime via RedefineClasses
// ---------------------------------------------------------------------------

static void CmdRedefineClass(jvmtiEnv* jvmti, JNIEnv* jni, const char* json) {
    char class_sig[256] = {0};
    if (!json_get_string(json, "class_sig", class_sig, sizeof(class_sig))) {
        SendError("redefine_class: missing class_sig");
        return;
    }

    // Locate dex_b64 in-place (may be hundreds of KB — avoid fixed-size copy)
    int b64_len = 0;
    const char* b64_ptr = json_find_string(json, "dex_b64", &b64_len);
    if (!b64_ptr || b64_len <= 0) {
        SendError("redefine_class: missing dex_b64");
        return;
    }

    // Decode base64 -> raw DEX bytes
    int dex_max = b64_len * 3 / 4 + 4;
    unsigned char* dex_bytes = (unsigned char*)malloc(dex_max);
    if (!dex_bytes) {
        SendError("redefine_class: out of memory for DEX buffer (%d bytes)", dex_max);
        return;
    }
    int dex_len = base64_decode(b64_ptr, b64_len, dex_bytes, dex_max);
    if (dex_len <= 0) {
        free(dex_bytes);
        SendError("redefine_class: base64 decode failed (b64_len=%d)", b64_len);
        return;
    }

    // Find the live jclass by signature
    jclass klass = FindClassBySig(jvmti, jni, class_sig);
    if (!klass) {
        free(dex_bytes);
        SendError("redefine_class: class not found: %s", class_sig);
        return;
    }

    // Diagnostic: log DEX header fields and verify Adler-32 before calling RedefineClasses
    if (dex_len >= 112) {
        uint32_t file_size   = (uint32_t)dex_bytes[32] | ((uint32_t)dex_bytes[33] << 8)
                             | ((uint32_t)dex_bytes[34] << 16) | ((uint32_t)dex_bytes[35] << 24);
        uint32_t header_size = (uint32_t)dex_bytes[36] | ((uint32_t)dex_bytes[37] << 8)
                             | ((uint32_t)dex_bytes[38] << 16) | ((uint32_t)dex_bytes[39] << 24);
        uint32_t endian_tag  = (uint32_t)dex_bytes[40] | ((uint32_t)dex_bytes[41] << 8)
                             | ((uint32_t)dex_bytes[42] << 16) | ((uint32_t)dex_bytes[43] << 24);
        uint32_t cdefs_size  = (uint32_t)dex_bytes[96] | ((uint32_t)dex_bytes[97] << 8)
                             | ((uint32_t)dex_bytes[98] << 16) | ((uint32_t)dex_bytes[99] << 24);
        uint32_t stored_cksum = (uint32_t)dex_bytes[8]  | ((uint32_t)dex_bytes[9]  << 8)
                              | ((uint32_t)dex_bytes[10] << 16) | ((uint32_t)dex_bytes[11] << 24);
        // Compute Adler-32 of bytes [12..dex_len)
        uint32_t s1 = 1, s2 = 0;
        for (int i = 12; i < dex_len; i++) {
            s1 = (s1 + dex_bytes[i]) % 65521u;
            s2 = (s2 + s1)           % 65521u;
        }
        uint32_t comp_cksum = (s2 << 16) | s1;
        ALOGI("[DBG] RedefineClasses: dex_len=%d header.file_size=%u header_size=%u endian=%08x class_defs_size=%u magic=%.7s",
              dex_len, file_size, header_size, endian_tag, cdefs_size, (char*)dex_bytes);
        ALOGI("[DBG] RedefineClasses: adler32 stored=%08x computed=%08x %s",
              stored_cksum, comp_cksum,
              stored_cksum == comp_cksum ? "OK" : "MISMATCH!");
        // Write DEX to /data/local/tmp/patch_debug.dex for offline inspection
        FILE* f = fopen("/data/local/tmp/patch_debug.dex", "wb");
        if (f) { fwrite(dex_bytes, 1, dex_len, f); fclose(f); ALOGI("[DBG] Wrote /data/local/tmp/patch_debug.dex"); }
        else   { ALOGI("[DBG] Could not write /data/local/tmp/patch_debug.dex (may need adb root)"); }
    }

    jvmtiClassDefinition def;
    def.klass            = klass;
    def.class_byte_count = (jint)dex_len;
    def.class_bytes      = dex_bytes;

    // Diagnostic: confirm capability is present; retry AddCapabilities if not
    {
        jvmtiCapabilities cur;
        memset(&cur, 0, sizeof(cur));
        jvmti->GetCapabilities(&cur);
        ALOGI("[DBG] RedefineClasses pre-check: can_redefine=%d can_retransform=%d",
              cur.can_redefine_classes, cur.can_retransform_classes);
        if (!cur.can_redefine_classes) {
            ALOGW("[DBG] can_redefine_classes not set — attempting AddCapabilities retry");
            jvmtiCapabilities retry;
            memset(&retry, 0, sizeof(retry));
            retry.can_redefine_classes = 1;
            jvmtiError caperr = jvmti->AddCapabilities(&retry);
            ALOGI("[DBG] AddCapabilities retry: err=%d", (int)caperr);
        }
    }

    jvmtiError err = jvmti->RedefineClasses(1, &def);

    jni->DeleteGlobalRef(klass);
    free(dex_bytes);

    if (err != JVMTI_ERROR_NONE) {
        ALOGE("[DBG] RedefineClasses failed for %s: err=%d", class_sig, (int)err);
        JsonBuf jb;
        json_start(&jb);
        json_add_string(&jb, "type", "redefine_error");
        json_add_string(&jb, "class_sig", class_sig);
        json_add_int(&jb, "err", (int)err);
        json_end(&jb);
        SendToClient(jb.buf);
    } else {
        ALOGI("[DBG] RedefineClasses OK: %s (%d bytes)", class_sig, dex_len);

        // If the server requested an auto-ForceEarlyReturn (field "return_value" present)
        // and a thread is currently suspended at a breakpoint, push a force_return command
        // to the suspended thread's command queue so the patch takes effect immediately
        // (without needing to wait for the method to be re-entered).
        int fr_value = 0;
        if (json_get_int(json, "return_value", &fr_value) && g_dbg.thread_suspended
                && g_dbg.cap_force_early_return) {
            DebuggerCommand dcmd;
            strncpy(dcmd.cmd, "force_return", sizeof(dcmd.cmd) - 1);
            dcmd.cmd[sizeof(dcmd.cmd) - 1] = '\0';
            snprintf(dcmd.raw, sizeof(dcmd.raw),
                     "{\"cmd\":\"force_return\",\"return_value\":%d}", fr_value);
            pthread_mutex_lock(&g_dbg.queue_mutex);
            g_dbg.cmd_queue.push_back(dcmd);
            pthread_cond_signal(&g_dbg.queue_cond);
            pthread_mutex_unlock(&g_dbg.queue_mutex);
            ALOGI("[DBG] RedefineClasses OK: queued force_return(value=%d)", fr_value);
        }

        JsonBuf jb;
        json_start(&jb);
        json_add_string(&jb, "type", "redefine_ok");
        json_add_string(&jb, "class_sig", class_sig);
        json_end(&jb);
        SendToClient(jb.buf);
    }
}

// ---------------------------------------------------------------------------
// Early-attach gate release — delete the gate file so the smali wait loop exits
// ---------------------------------------------------------------------------

static void CmdGateRelease(jvmtiEnv* jvmti, JNIEnv* jni, const char*) {
    // Use FindClassBySig (JVMTI-based) -- jni->FindClass won't find app classes
    // from the native socket recv thread (wrong classloader).
    jclass klass = FindClassBySig(jvmti, jni, "Lcom/dexbgd/GateWait;");
    if (!klass) {
        ALOGW("[DBG] gate_release: GateWait class not found (--gate not used?)");
        return;
    }
    jfieldID fid = jni->GetStaticFieldID(klass, "released", "Z");
    if (fid) {
        jni->SetStaticBooleanField(klass, fid, JNI_TRUE);
        ALOGI("[DBG] gate_release: GateWait.released = true");
    } else {
        jni->ExceptionClear();
        ALOGW("[DBG] gate_release: GateWait.released field not found");
    }
    jni->DeleteGlobalRef(klass);
}

// ---------------------------------------------------------------------------
// Command dispatch — called from socket recv thread
// ---------------------------------------------------------------------------

// Handle global commands (bp_set, cls, methods, etc.) that can run from any context.
// Called from both DispatchCommand and the CmdSuspend inline command loop.
static void DispatchGlobalCommand(jvmtiEnv* jvmti, JNIEnv* jni,
                                   const char* cmd, const char* json) {
    if (strcmp(cmd, "cls") == 0) {
        CmdClasses(jvmti, jni, json);
    } else if (strcmp(cmd, "methods") == 0) {
        CmdMethods(jvmti, jni, json);
    } else if (strcmp(cmd, "fields") == 0) {
        CmdFields(jvmti, jni, json);
    } else if (strcmp(cmd, "threads") == 0) {
        CmdThreads(jvmti, jni, json);
    } else if (strcmp(cmd, "dis") == 0) {
        CmdDisassemble(jvmti, jni, json);
    } else if (strcmp(cmd, "bp_set") == 0) {
        CmdBpSet(jvmti, jni, json);
    } else if (strcmp(cmd, "bp_set_deopt") == 0) {
        // Set breakpoint then force ART deoptimization via RetransformClasses.
        // Workaround for repacked APKs where SetBreakpoint succeeds but
        // OnBreakpoint never fires because ART doesn't deoptimize the method.
        CmdBpSet(jvmti, jni, json);
        char class_sig[256];
        if (json_get_string(json, "class", class_sig, sizeof(class_sig))) {
            jclass klass = FindClassBySig(jvmti, jni, class_sig);
            if (klass) {
                jvmtiError err = jvmti->RetransformClasses(1, &klass);
                if (err == JVMTI_ERROR_NONE) {
                    ALOGI("[DBG] bp_set_deopt: RetransformClasses(%s) OK - forced deopt", class_sig);
                } else {
                    ALOGW("[DBG] bp_set_deopt: RetransformClasses(%s) failed: err=%d", class_sig, (int)err);
                }
                jni->DeleteGlobalRef(klass);
            }
        }
    } else if (strcmp(cmd, "bp_clear") == 0) {
        CmdBpClear(jvmti, jni, json);
    } else if (strcmp(cmd, "bp_list") == 0) {
        CmdBpList(jvmti, jni, json);
    } else if (strcmp(cmd, "memdump") == 0) {
        CmdMemDump(jvmti, jni, json);
    } else if (strcmp(cmd, "heap") == 0) {
        CmdHeap(jvmti, jni, json);
    } else if (strcmp(cmd, "heap_strings") == 0) {
        CmdHeapStrings(jvmti, jni, json);
    } else if (strcmp(cmd, "suspend") == 0) {
        CmdSuspend(jvmti, jni, json);
    } else if (strcmp(cmd, "dex_read") == 0) {
        CmdDexRead(jvmti, jni, json);
    } else if (strcmp(cmd, "record_start") == 0) {
        CmdRecordStart(jvmti, jni, json);
    } else if (strcmp(cmd, "record_stop") == 0) {
        CmdRecordStop(jvmti, jni, json);
    } else if (strcmp(cmd, "redefine_class") == 0) {
        CmdRedefineClass(jvmti, jni, json);
    } else if (strcmp(cmd, "gate_release") == 0) {
        CmdGateRelease(jvmti, jni, json);
    } else if (strcmp(cmd, "jni_monitor_start") == 0) {
        CmdJniMonitorStart(jvmti, jni, json);
    } else if (strcmp(cmd, "jni_monitor_stop") == 0) {
        CmdJniMonitorStop(jvmti, jni, json);
    } else if (strcmp(cmd, "jni_redirect_set") == 0) {
        CmdJniRedirectSet(jvmti, jni, json);
    } else if (strcmp(cmd, "jni_redirect_clear") == 0) {
        CmdJniRedirectClear(jvmti, jni, json);
    } else {
        SendError("unknown cmd: %s", cmd);
    }
}

static void DispatchCommand(jvmtiEnv* jvmti, JNIEnv* jni, const char* json) {
    char cmd[64] = "";
    if (!json_get_string(json, "cmd", cmd, sizeof(cmd))) {
        ALOGW("[DBG] No 'cmd' in message: %.100s", json);
        return;
    }

    ALOGI("[DBG] Dispatch: %s", cmd);

    // Special case: 'continue' during active stepping cancels the step so the
    // thread runs freely. Normally 'continue' is only processed by a thread
    // blocked in DebuggerCommandLoop; but when the 5-second STEPPING safety
    // timeout fires (or the user presses F5 during a stuck step), the thread
    // is running and thread_suspended is false, so we handle it here directly.
    if (strcmp(cmd, "continue") == 0 && !g_dbg.thread_suspended &&
            g_dbg.step_mode != STEP_NONE) {
        ALOGI("[DBG] Continue received during active stepping — canceling step");
        jvmti->SetEventNotificationMode(JVMTI_DISABLE, JVMTI_EVENT_SINGLE_STEP, nullptr);
        g_dbg.step_mode = STEP_NONE;
        // Do NOT call ClearStepThread here: DeleteGlobalRef from the socket thread
        // races with any in-flight OnSingleStep callback. step_thread will be
        // cleaned up by the next SetStepThread call.
        JsonBuf jb;
        json_start(&jb);
        json_add_string(&jb, "type", "resumed");
        json_end(&jb);
        SendToClient(jb.buf);
        return;
    }

    // Commands that require a suspended thread — push to queue
    if (strcmp(cmd, "continue") == 0 ||
        strcmp(cmd, "step_into") == 0 ||
        strcmp(cmd, "step_over") == 0 ||
        strcmp(cmd, "step_out") == 0 ||
        strcmp(cmd, "step_out2") == 0 ||
        strcmp(cmd, "force_return") == 0 ||
        strcmp(cmd, "locals") == 0 ||
        strcmp(cmd, "regs") == 0 ||
        strcmp(cmd, "stack") == 0 ||
        strcmp(cmd, "inspect") == 0 ||
        strcmp(cmd, "eval") == 0 ||
        strcmp(cmd, "hexdump") == 0 ||
        strcmp(cmd, "dex_dump") == 0 ||
        strcmp(cmd, "set_local") == 0) {

        if (!g_dbg.thread_suspended) {
            // Stale refresh from server arriving between steps — silently drop.
            return;
        }

        DebuggerCommand dcmd;
        strncpy(dcmd.cmd, cmd, sizeof(dcmd.cmd) - 1);
        dcmd.cmd[sizeof(dcmd.cmd) - 1] = '\0';
        strncpy(dcmd.raw, json, sizeof(dcmd.raw) - 1);
        dcmd.raw[sizeof(dcmd.raw) - 1] = '\0';

        pthread_mutex_lock(&g_dbg.queue_mutex);
        g_dbg.cmd_queue.push_back(dcmd);
        pthread_cond_signal(&g_dbg.queue_cond);
        pthread_mutex_unlock(&g_dbg.queue_mutex);
        return;
    }

    // Also allow dis from suspended context (push to queue if suspended)
    if (strcmp(cmd, "dis") == 0 && g_dbg.thread_suspended) {
        DebuggerCommand dcmd;
        strncpy(dcmd.cmd, cmd, sizeof(dcmd.cmd) - 1);
        dcmd.cmd[sizeof(dcmd.cmd) - 1] = '\0';
        strncpy(dcmd.raw, json, sizeof(dcmd.raw) - 1);
        dcmd.raw[sizeof(dcmd.raw) - 1] = '\0';

        pthread_mutex_lock(&g_dbg.queue_mutex);
        g_dbg.cmd_queue.push_back(dcmd);
        pthread_cond_signal(&g_dbg.queue_cond);
        pthread_mutex_unlock(&g_dbg.queue_mutex);
        return;
    }

    // redefine_class while suspended must run on the app thread to avoid a
    // deadlock: jvmti->RedefineClasses() calls ART SuspendAll, but the app
    // thread is blocked in pthread_cond_wait inside the JVMTI breakpoint
    // callback and cannot reach a checkpoint.  DEX can be hundreds of KB so
    // we heap-allocate the JSON copy rather than stuffing it in raw[4096].
    if (strcmp(cmd, "redefine_class") == 0 && g_dbg.thread_suspended) {
        char* json_copy = strdup(json);
        if (!json_copy) {
            SendError("redefine_class: out of memory for JSON copy");
            return;
        }
        pthread_mutex_lock(&g_dbg.queue_mutex);
        free(g_dbg.pending_redefine_json);  // drop any stale previous (shouldn't exist)
        g_dbg.pending_redefine_json = json_copy;
        DebuggerCommand dcmd;
        strncpy(dcmd.cmd, "redefine_class", sizeof(dcmd.cmd) - 1);
        dcmd.cmd[sizeof(dcmd.cmd) - 1] = '\0';
        dcmd.raw[0] = '\0';  // not used — actual JSON is in pending_redefine_json
        g_dbg.cmd_queue.push_back(dcmd);
        pthread_cond_signal(&g_dbg.queue_cond);
        pthread_mutex_unlock(&g_dbg.queue_mutex);
        return;
    }

    // Global commands — execute directly on socket thread
    DispatchGlobalCommand(jvmti, jni, cmd, json);
}

// ---------------------------------------------------------------------------
// Recv loop — reads from client socket, splits on newlines, dispatches
// ---------------------------------------------------------------------------

static void RecvLoop(jvmtiEnv* jvmti, JNIEnv* jni) {
    // Dynamic recv buffer — grows to accommodate large commands (e.g. redefine_class dex_b64).
    int buf_cap = 128 * 1024;  // 128 KB initial
    char* buf = (char*)malloc(buf_cap);
    if (!buf) {
        ALOGE("[DBG] RecvLoop: malloc failed");
        return;
    }
    int buf_len = 0;

    while (g_dbg.running && g_dbg.client_fd >= 0) {
        // Grow buffer when less than 25% space remains
        if (buf_cap - buf_len < buf_cap / 4) {
            int new_cap = buf_cap * 2;
            char* new_buf = (char*)realloc(buf, new_cap);
            if (!new_buf) {
                ALOGE("[DBG] RecvLoop: realloc to %d failed, discarding", new_cap);
                buf_len = 0;
                continue;
            }
            buf = new_buf;
            buf_cap = new_cap;
            ALOGI("[DBG] RecvLoop: buffer grown to %d KB", buf_cap / 1024);
        }

        int space = buf_cap - buf_len - 1;
        int n = recv(g_dbg.client_fd, buf + buf_len, space, 0);
        if (n <= 0) {
            if (n == 0) {
                ALOGI("[DBG] Client disconnected");
            } else {
                ALOGW("[DBG] recv error: %s", strerror(errno));
            }
            break;
        }
        buf_len += n;
        buf[buf_len] = '\0';

        // Process complete lines
        char* start = buf;
        char* nl;
        while ((nl = strchr(start, '\n')) != nullptr) {
            *nl = '\0';
            if (start[0] != '\0') {
                DispatchCommand(jvmti, jni, start);
            }
            start = nl + 1;
        }

        // Move remaining partial line to front of buffer
        int remaining = buf_len - (start - buf);
        if (remaining > 0 && start != buf) {
            memmove(buf, start, remaining);
        }
        buf_len = remaining;
    }

    free(buf);
}

// ---------------------------------------------------------------------------
// Socket thread
// ---------------------------------------------------------------------------

static void* SocketThread(void* arg) {
    ALOGI("[DBG] Socket thread started");

    // Attach to JVM
    JNIEnv* jni = nullptr;
    g_dbg.vm->AttachCurrentThread(&jni, nullptr);

    // Create abstract Unix domain socket (SELinux allows this for apps)
    g_dbg.server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (g_dbg.server_fd < 0) {
        ALOGE("[DBG] socket() failed: %s", strerror(errno));
        g_dbg.vm->DetachCurrentThread();
        return nullptr;
    }

    // Move to a high fd to protect against JDWP/platform fd cleanup that runs
    // concurrently during am-start-D (closes low-numbered fds it doesn't own).
    {
        int hfd = fcntl(g_dbg.server_fd, F_DUPFD, 200);
        if (hfd >= 0) {
            close(g_dbg.server_fd);
            g_dbg.server_fd = hfd;
            ALOGI("[DBG] server_fd moved to %d", hfd);
        }
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    // Abstract namespace: sun_path[0] = '\0', then the name
    addr.sun_path[0] = '\0';
    strncpy(addr.sun_path + 1, kSocketName, sizeof(addr.sun_path) - 2);
    socklen_t addr_len = offsetof(struct sockaddr_un, sun_path) + 1 + strlen(kSocketName);

    if (bind(g_dbg.server_fd, (struct sockaddr*)&addr, addr_len) < 0) {
        ALOGE("[DBG] bind(@%s) failed: %s", kSocketName, strerror(errno));
        close(g_dbg.server_fd);
        g_dbg.server_fd = -1;
        g_dbg.vm->DetachCurrentThread();
        return nullptr;
    }

    if (listen(g_dbg.server_fd, 1) < 0) {
        ALOGE("[DBG] listen() failed: %s", strerror(errno));
        close(g_dbg.server_fd);
        g_dbg.server_fd = -1;
        g_dbg.vm->DetachCurrentThread();
        return nullptr;
    }

    ALOGI("[DBG] Listening on abstract socket @%s", kSocketName);

    // Accept loop — one client at a time
    while (g_dbg.running) {
        struct sockaddr_un client_addr;
        socklen_t client_len = sizeof(client_addr);
        int cfd = accept(g_dbg.server_fd, (struct sockaddr*)&client_addr, &client_len);
        if (cfd < 0) {
            if (errno == EBADF || errno == EINVAL) {
                // Something (JDWP init, platform cleanup) closed our fd.
                // Wait 1 s for initialization to settle, then recreate the socket.
                ALOGW("[DBG] accept() EBADF - recreating socket in 1s...");
                close(g_dbg.server_fd);
                g_dbg.server_fd = -1;
                sleep(1);

                int new_fd = socket(AF_UNIX, SOCK_STREAM, 0);
                if (new_fd >= 0) {
                    int hfd = fcntl(new_fd, F_DUPFD, 200);
                    if (hfd >= 0) { close(new_fd); new_fd = hfd; }

                    struct sockaddr_un ra;
                    memset(&ra, 0, sizeof(ra));
                    ra.sun_family = AF_UNIX;
                    ra.sun_path[0] = '\0';
                    strncpy(ra.sun_path + 1, kSocketName, sizeof(ra.sun_path) - 2);
                    socklen_t ra_len = offsetof(struct sockaddr_un, sun_path)
                                       + 1 + strlen(kSocketName);

                    if (bind(new_fd, (struct sockaddr*)&ra, ra_len) == 0 &&
                        listen(new_fd, 1) == 0) {
                        g_dbg.server_fd = new_fd;
                        ALOGI("[DBG] Socket recreated (fd=%d), listening @%s",
                              new_fd, kSocketName);
                        continue;
                    }
                    close(new_fd);
                }
                ALOGE("[DBG] Socket recreate failed: %s - thread exiting", strerror(errno));
                g_dbg.vm->DetachCurrentThread();
                return nullptr;
            }
            if (g_dbg.running) {
                ALOGW("[DBG] accept() failed: %s", strerror(errno));
            }
            continue;
        }

        ALOGI("[DBG] Client connected (fd=%d)", cfd);

        pthread_mutex_lock(&g_dbg.sock_mutex);
        g_dbg.client_fd = cfd;
        pthread_mutex_unlock(&g_dbg.sock_mutex);

        // Send connected event with capabilities
        {
            JsonBuf jb;
            json_start(&jb);
            json_add_string(&jb, "type", "connected");
            json_add_int(&jb, "pid", getpid());
            json_add_string(&jb, "version", "dexbgd-agent-1.0");

            // Read package name from /proc/self/cmdline (process name = package on Android)
            {
                char cmdline[256] = "";
                int cfd = open("/proc/self/cmdline", O_RDONLY);
                if (cfd >= 0) {
                    ssize_t n = read(cfd, cmdline, sizeof(cmdline) - 1);
                    if (n > 0) cmdline[n] = '\0';
                    close(cfd);
                }
                if (cmdline[0]) json_add_string(&jb, "package_name", cmdline);
            }

            // Add device info
            {
                char sdk[8] = "", rel[16] = "", model[64] = "";
                __system_property_get("ro.build.version.sdk", sdk);
                __system_property_get("ro.build.version.release", rel);
                __system_property_get("ro.product.model", model);
                char device_str[128];
                snprintf(device_str, sizeof(device_str), "%s (Android %s, API %s)", model, rel, sdk);
                json_add_string(&jb, "device", device_str);
                json_add_int(&jb, "api_level", atoi(sdk));
            }

            // Build capabilities object
            jvmtiCapabilities caps;
            memset(&caps, 0, sizeof(caps));
            g_dbg.jvmti->GetCapabilities(&caps);

            char caps_json[512];
            snprintf(caps_json, sizeof(caps_json),
                "{\"breakpoints\":%s,\"single_step\":%s,\"local_vars\":%s,"
                "\"line_numbers\":%s,\"bytecodes\":%s,\"tag_objects\":%s,"
                "\"force_early_return\":%s,\"pop_frame\":%s,\"frame_pop\":%s,"
                "\"redefine_classes\":%s,\"retransform_classes\":%s}",
                caps.can_generate_breakpoint_events ? "true" : "false",
                caps.can_generate_single_step_events ? "true" : "false",
                caps.can_access_local_variables ? "true" : "false",
                caps.can_get_line_numbers ? "true" : "false",
                caps.can_get_bytecodes ? "true" : "false",
                caps.can_tag_objects ? "true" : "false",
                caps.can_force_early_return ? "true" : "false",
                caps.can_pop_frame ? "true" : "false",
                caps.can_generate_frame_pop_events ? "true" : "false",
                caps.can_redefine_classes ? "true" : "false",
                caps.can_retransform_classes ? "true" : "false");
            json_add_raw(&jb, "capabilities", caps_json);

            json_end(&jb);
            SendToClient(jb.buf);
        }

        // Enter recv loop (blocks until disconnect)
        RecvLoop(g_dbg.jvmti, jni);

        // Client disconnected — clean up
        pthread_mutex_lock(&g_dbg.sock_mutex);
        close(g_dbg.client_fd);
        g_dbg.client_fd = -1;
        pthread_mutex_unlock(&g_dbg.sock_mutex);

        // Wake any thread blocked in DebuggerCommandLoop
        pthread_mutex_lock(&g_dbg.queue_mutex);
        pthread_cond_broadcast(&g_dbg.queue_cond);
        pthread_mutex_unlock(&g_dbg.queue_mutex);

        ALOGI("[DBG] Client disconnected, waiting for new connection");
    }

    close(g_dbg.server_fd);
    g_dbg.server_fd = -1;
    g_dbg.vm->DetachCurrentThread();
    ALOGI("[DBG] Socket thread exiting");
    return nullptr;
}

// ---------------------------------------------------------------------------
// StartDebugger — called from agent.cpp's SetupJvmtiAgent()
// ---------------------------------------------------------------------------

void StartDebugger(jvmtiEnv* jvmti, JavaVM* vm) {
    memset(&g_dbg, 0, sizeof(g_dbg));
    g_dbg.jvmti = jvmti;
    g_dbg.vm = vm;
    g_dbg.server_fd = -1;
    g_dbg.client_fd = -1;
    g_dbg.next_bp_id = 1;
    g_dbg.step_mode = STEP_NONE;
    g_dbg.step_thread = nullptr;
    g_dbg.thread_suspended = false;
    g_dbg.running = true;
    g_dbg.recording.store(false);
    g_dbg.call_seq.store(0);
    g_dbg.calls_this_second = 0;
    g_dbg.rate_limit_epoch = 0;
    g_dbg.pending_redefine_json = nullptr;
    g_dbg.jni_monitoring.store(false);
    g_dbg.jni_original_table = nullptr;
    memset(&g_dbg.jni_hooked_table, 0, sizeof(g_dbg.jni_hooked_table));
    g_dbg.jni_capture_count.store(0);
    pthread_mutex_init(&g_dbg.jni_redirect_mutex, nullptr);

    // Populate capability flags from what JVMTI actually granted
    {
        jvmtiCapabilities caps;
        memset(&caps, 0, sizeof(caps));
        jvmti->GetCapabilities(&caps);
        g_dbg.cap_bytecodes   = (caps.can_get_bytecodes != 0);
        g_dbg.cap_local_vars  = (caps.can_access_local_variables != 0);
        g_dbg.cap_breakpoints = (caps.can_generate_breakpoint_events != 0);
        g_dbg.cap_single_step = (caps.can_generate_single_step_events != 0);
        g_dbg.cap_tag_objects = (caps.can_tag_objects != 0);
        g_dbg.cap_line_numbers = (caps.can_get_line_numbers != 0);
        g_dbg.cap_method_exit = (caps.can_generate_method_exit_events != 0);
        g_dbg.cap_force_early_return = (caps.can_force_early_return != 0);
        g_dbg.cap_pop_frame = (caps.can_pop_frame != 0);
        g_dbg.cap_frame_pop = (caps.can_generate_frame_pop_events != 0);
        ALOGI("[DBG] Caps: bytecodes=%d locals=%d bp=%d step=%d tags=%d lines=%d exit=%d force_ret=%d pop_frame=%d frame_pop=%d",
              g_dbg.cap_bytecodes, g_dbg.cap_local_vars, g_dbg.cap_breakpoints,
              g_dbg.cap_single_step, g_dbg.cap_tag_objects, g_dbg.cap_line_numbers,
              g_dbg.cap_method_exit, g_dbg.cap_force_early_return, g_dbg.cap_pop_frame,
              g_dbg.cap_frame_pop);
    }

    pthread_mutex_init(&g_dbg.sock_mutex, nullptr);
    pthread_mutex_init(&g_dbg.queue_mutex, nullptr);
    pthread_cond_init(&g_dbg.queue_cond, nullptr);

    pthread_t tid;
    if (pthread_create(&tid, nullptr, SocketThread, nullptr) != 0) {
        ALOGE("[DBG] Failed to create socket thread: %s", strerror(errno));
        return;
    }
    pthread_detach(tid);

    ALOGI("[DBG] Debugger started, socket thread launched");
}
