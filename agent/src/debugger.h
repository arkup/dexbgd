#ifndef DEXBGD_DEBUGGER_H
#define DEXBGD_DEBUGGER_H

#include <jni.h>
#include <jvmti.h>
#include <pthread.h>
#include <vector>
#include <string>
#include <map>
#include <atomic>

// ---------------------------------------------------------------------------
// Debugger types
// ---------------------------------------------------------------------------

enum StepMode {
    STEP_NONE = 0,
    STEP_INTO,
    STEP_OVER,
    STEP_OUT
};

struct Breakpoint {
    int id;
    jmethodID method;
    jlocation location;
    char class_sig[256];
    char method_name[128];
    char method_sig_str[256];
};

// A breakpoint that cannot be set yet because its class is not loaded.
// Queued in g_pending_bps; set via CLASS_PREPARE event.
struct PendingBreakpoint {
    int bp_id;
    char class_sig[256];
    char method_name[128];
    char method_sig[128];   // empty string = match any overload
};

// Command queued from socket thread → app thread (blocked at breakpoint)
struct DebuggerCommand {
    char cmd[64];
    char raw[4096];  // full JSON line for commands that need extra params
};

// A redirected JNI native method: original pointer saved so it can be restored.
struct JniRedirect {
    void* original_fnptr;    // captured from RegisterNatives hook, or null if unknown
    char  class_sig[256];
    char  method_name[128];
    char  method_sig[256];
    char  action[32];        // "block", "true", "spoof"
    int64_t spoof_value;
};

struct DebuggerState {
    jvmtiEnv* jvmti;
    JavaVM* vm;

    // Socket
    int server_fd;
    int client_fd;
    pthread_mutex_t sock_mutex;

    // Command queue (socket thread → suspended app thread)
    pthread_mutex_t queue_mutex;
    pthread_cond_t queue_cond;
    std::vector<DebuggerCommand> cmd_queue;

    // Breakpoints
    std::vector<Breakpoint> breakpoints;
    int next_bp_id;

    // Stepping state (per-thread, single-thread for Phase 1)
    StepMode step_mode;
    jthread step_thread;
    int step_target_depth;

    // Is a thread currently suspended in DebuggerCommandLoop?
    std::atomic<bool> thread_suspended;

    bool running;

    // JNI monitor / redirect state
    std::atomic<bool> jni_monitoring;   // toggled by jni_monitor_start/stop
    JNINativeInterface jni_hooked_table;          // our patched vtable copy
    const JNINativeInterface* jni_original_table; // ART's original vtable
    std::map<std::string, JniRedirect> jni_redirects; // key = "sig:name:msig"
    pthread_mutex_t jni_redirect_mutex;
    std::atomic<int> jni_capture_count; // total RegisterNatives captures this session

    // Call recording state
    std::atomic<bool> recording;        // toggled by record_start/record_stop
    std::atomic<int> call_seq;          // monotonic sequence number
    int calls_this_second;              // rate-limit counter
    long long rate_limit_epoch;         // second boundary (monotonic ns / 1e9)
    bool cap_method_exit;               // capability flag for method exit events

    // Capability flags — set once during setup, checked before JVMTI calls
    bool cap_bytecodes;
    bool cap_local_vars;
    bool cap_breakpoints;
    bool cap_single_step;
    bool cap_tag_objects;
    bool cap_line_numbers;
    bool cap_suspend;
    bool cap_force_early_return;
    bool cap_pop_frame;
    bool cap_frame_pop;

    // Large redefine JSON (heap-allocated, may be hundreds of KB).
    // Set by socket thread, consumed by app thread in DebuggerCommandLoop.
    // Protected by queue_mutex.
    char* pending_redefine_json;
};

// ---------------------------------------------------------------------------
// Public API (called from agent.cpp)
// ---------------------------------------------------------------------------

// Start the debugger socket thread. Call from SetupJvmtiAgent().
void StartDebugger(jvmtiEnv* jvmti, JavaVM* vm);

// Send a JSON-line to the connected client. Thread-safe.
void SendToClient(const char* json);

// Called from OnBreakpoint callback in agent.cpp.
// Sends bp_hit event, then blocks in command loop until continue/step.
void DebuggerCommandLoop(jvmtiEnv* jvmti, JNIEnv* jni, jthread thread,
                         jmethodID method, jlocation location, int bp_id);

// Called from OnSingleStep callback in agent.cpp.
// Returns true if we should stop (enter command loop), false to keep stepping.
bool ShouldStopStepping(jvmtiEnv* jvmti, JNIEnv* jni, jthread thread,
                        jmethodID method, jlocation location);

// Called from OnFramePop callback in agent.cpp (sout2 fast step-out).
// Sends frame_pop event with return value, then enters command loop at caller.
void HandleFramePop(jvmtiEnv* jvmti, JNIEnv* jni, jthread thread,
                    jmethodID method, jboolean was_exception);

// Called from OnThreadEnd callback in agent.cpp.
// If the dying thread is the current step thread, cleans up step state and
// notifies the server so it doesn't hang in STEPPING.
void HandleStepThreadEnd(jvmtiEnv* jvmti, JNIEnv* jni, jthread thread);

// Look up breakpoint id by method+location. Returns -1 if not found.
int FindBreakpointId(jmethodID method, jlocation location);

// Access the global debugger state
DebuggerState* GetDebuggerState();

// Format an object's value as a human-readable string (for recording/display)
// detailed=true (default): crypto-aware formatting (SecretKeySpec, IvParameterSpec, etc.)
// detailed=false: fast path for hot call recording — skips crypto checks
void FormatObjectValue(JNIEnv* jni, jobject obj, char* out, size_t out_len, bool detailed = true);

// Called from agent.cpp's OnClassPrepare callback.
// Checks g_pending_bps for any BPs waiting on this class, sets them, and
// sends bp_set_ok to the server for each one.
void HandleClassPrepare(jvmtiEnv* jvmti, JNIEnv* jni, jthread thread, jclass klass);

// Called from OnThreadStart callback in agent.cpp.
// If JNI monitoring is active, patches the new thread's JNIEnv vtable.
void HandleThreadStart(jvmtiEnv* jvmti, JNIEnv* jni, jthread thread);

// Patch a JNIEnv's function table to intercept RegisterNatives.
// Safe to call multiple times on the same env (idempotent).
void PatchJniEnvForMonitor(JNIEnv* env);

#endif // DEXBGD_DEBUGGER_H
