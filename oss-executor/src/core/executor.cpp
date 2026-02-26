#include "executor.hpp"
#include "utils/logger.hpp"
#include "utils/config.hpp"

#include <filesystem>
#include <fstream>
#include <chrono>
#include <algorithm>
#include <vector>

namespace oss {

Executor& Executor::instance() {
    static Executor inst;
    return inst;
}

Executor::Executor()  = default;
Executor::~Executor() { shutdown(); }

void Executor::init() {
    if (initialized_) return;

    LOG_INFO("Initializing OSS Executor...");
    if (status_cb_) status_cb_("Initializing...");

    // ── Initialize Lua engine with timing ──
    auto t0 = std::chrono::steady_clock::now();

    if (!lua_.init()) {
        LOG_ERROR("Failed to initialize Lua engine");
        if (error_cb_)  error_cb_("Lua engine initialization failed");
        if (status_cb_) status_cb_("Init failed — Lua engine error");
        return;
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                  std::chrono::steady_clock::now() - t0).count();
    LOG_INFO("Lua engine initialized in {}ms", ms);

    // ── Wire Lua output/error to our callbacks ──
    lua_.set_output_callback([this](const std::string& msg) {
        if (output_cb_) output_cb_(msg);
    });

    lua_.set_error_callback([this](const LuaError& err) {
        std::string msg = err.message;
        if (err.line > 0) {
            msg = "[" + err.source + ":" + std::to_string(err.line) + "] " + msg;
        }
        if (error_cb_) error_cb_(msg);
    });

    // ── Injection status forwarding ──
    Injection::instance().set_status_callback(
        [this](InjectionStatus /*status*/, const std::string& msg) {
            if (status_cb_) status_cb_(msg);
        }
    );

    // ── Ensure workspace exists ──
    auto workspace = Config::instance().home_dir() + "/workspace";
    std::filesystem::create_directories(workspace);

    // ── Optional auto-scan ──
    if (Config::instance().get<bool>("executor.auto_inject", false)) {
        Injection::instance().start_auto_scan();
    }

    initialized_ = true;
    if (status_cb_) status_cb_("Ready");
    LOG_INFO("OSS Executor initialized successfully");
}

void Executor::shutdown() {
    if (!initialized_) return;

    LOG_INFO("Shutting down OSS Executor...");
    Injection::instance().stop_auto_scan();
    lua_.shutdown();
    initialized_ = false;
}

void Executor::execute_script(const std::string& script) {
    if (!initialized_) {
        if (error_cb_) error_cb_("Executor not initialized");
        return;
    }
    if (script.empty()) {
        if (error_cb_) error_cb_("Empty script");
        return;
    }

    if (status_cb_) status_cb_("Executing...");

    bool ok = lua_.execute(script, "=user_script");

    if (ok) {
        if (status_cb_) status_cb_("Executed ✓");
    } else {
        if (status_cb_) status_cb_("Execution failed ✗");
    }
}

void Executor::execute_file(const std::string& path) {
    if (!initialized_) {
        if (error_cb_) error_cb_("Executor not initialized");
        return;
    }

    std::ifstream file(path);
    if (!file.is_open()) {
        if (error_cb_) error_cb_("Cannot open file: " + path);
        return;
    }

    std::string content((std::istreambuf_iterator<char>(file)),
                         std::istreambuf_iterator<char>());
    execute_script(content);
}

void Executor::cancel_execution() {
    lua_.stop();
    if (status_cb_) status_cb_("Cancelled");
    LOG_INFO("Execution cancelled by user");
}

void Executor::auto_execute() {
    std::string dir = Config::instance().home_dir() + "/scripts/autoexec";

    if (!std::filesystem::exists(dir) ||
        !std::filesystem::is_directory(dir)) {
        return;
    }

    std::vector<std::filesystem::path> scripts;
    for (const auto& entry : std::filesystem::directory_iterator(dir)) {
        if (!entry.is_regular_file()) continue;
        auto ext = entry.path().extension().string();
        if (ext == ".lua" || ext == ".luau") {
            scripts.push_back(entry.path());
        }
    }

    std::sort(scripts.begin(), scripts.end());

    for (const auto& s : scripts) {
        LOG_INFO("Auto-executing: {}", s.filename().string());
        if (output_cb_) {
            output_cb_("[autoexec] Running " + s.filename().string());
        }
        execute_file(s.string());
    }

    if (!scripts.empty()) {
        LOG_INFO("Auto-executed {} scripts", scripts.size());
    }
}

void Executor::set_output_callback(std::function<void(const std::string&)> cb) {
    output_cb_ = std::move(cb);
}
void Executor::set_error_callback(std::function<void(const std::string&)> cb) {
    error_cb_ = std::move(cb);
}
void Executor::set_status_callback(std::function<void(const std::string&)> cb) {
    status_cb_ = std::move(cb);
}

} // namespace oss
