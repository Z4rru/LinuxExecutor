#include "executor.hpp"
#include <filesystem>

namespace oss {

bool Executor::init() {
    LOG_INFO("Initializing OSS Executor...");
    
    // Initialize Lua engine
    if (!lua_engine_.init()) {
        LOG_ERROR("Failed to initialize Lua engine");
        return false;
    }

    // Wire up callbacks
    lua_engine_.set_output_callback([this](const std::string& msg) {
        if (output_cb_) output_cb_(msg);
    });

    lua_engine_.set_error_callback([this](const LuaError& err) {
        std::string formatted = "[Error]";
        if (err.line >= 0) formatted += " Line " + std::to_string(err.line) + ":";
        formatted += " " + err.message;
        if (error_cb_) error_cb_(formatted);
    });

    // Set up injection status callback
    Injection::instance().set_status_callback(
        [this](InjectionStatus status, const std::string& msg) {
            if (status_cb_) status_cb_(msg);
        }
    );

    // Create workspace directory
    std::string workspace = Config::instance().home_dir() + "/workspace";
    std::filesystem::create_directories(workspace);

    // Start worker thread
    running_ = true;
    worker_thread_ = std::thread(&Executor::worker_loop, this);

    // Start auto-scanning for Roblox
    if (Config::instance().get<bool>("executor.auto_inject", false)) {
        Injection::instance().start_auto_scan();
    }

    LOG_INFO("OSS Executor initialized successfully");
    if (status_cb_) status_cb_("Ready");
    
    return true;
}

void Executor::shutdown() {
    running_ = false;
    Injection::instance().stop_auto_scan();
    
    if (worker_thread_.joinable()) {
        worker_thread_.join();
    }
    
    lua_engine_.shutdown();
    LOG_INFO("OSS Executor shut down");
}

bool Executor::execute_script(const std::string& script) {
    if (script.empty()) return false;
    
    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        script_queue_.push(script);
    }
    
    return true;
}

bool Executor::execute_file(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        if (error_cb_) error_cb_("Cannot open file: " + path);
        return false;
    }
    
    std::string content((std::istreambuf_iterator<char>(file)),
                         std::istreambuf_iterator<char>());
    return execute_script(content);
}

void Executor::auto_execute() {
    std::string autoexec_dir = Config::instance().home_dir() + "/scripts/autoexec";
    
    if (!std::filesystem::exists(autoexec_dir)) return;
    
    std::vector<std::filesystem::path> scripts;
    for (const auto& entry : std::filesystem::directory_iterator(autoexec_dir)) {
        if (entry.path().extension() == ".lua" || entry.path().extension() == ".luau") {
            scripts.push_back(entry.path());
        }
    }
    
    std::sort(scripts.begin(), scripts.end());
    
    for (const auto& script : scripts) {
        LOG_INFO("Auto-executing: {}", script.filename().string());
        execute_file(script.string());
    }
}

bool Executor::is_attached() const {
    auto status = Injection::instance().status();
    return status == InjectionStatus::Injected || 
           status == InjectionStatus::Found;
}

std::string Executor::status_text() const {
    switch (Injection::instance().status()) {
        case InjectionStatus::Idle: return "Idle";
        case InjectionStatus::Scanning: return "Scanning...";
        case InjectionStatus::Found: return "Found Roblox";
        case InjectionStatus::Attaching: return "Attaching...";
        case InjectionStatus::Injected: return "Injected ✓";
        case InjectionStatus::Failed: return "Failed ✗";
        case InjectionStatus::Detached: return "Detached";
    }
    return "Unknown";
}

void Executor::cancel_execution() {
    lua_engine_.stop();
    
    // Clear queue
    std::lock_guard<std::mutex> lock(queue_mutex_);
    std::queue<std::string> empty;
    std::swap(script_queue_, empty);
    
    // Reinit engine
    lua_engine_.reset();
    lua_engine_.set_output_callback([this](const std::string& msg) {
        if (output_cb_) output_cb_(msg);
    });
    lua_engine_.set_error_callback([this](const LuaError& err) {
        if (error_cb_) error_cb_(err.message);
    });
}

void Executor::worker_loop() {
    while (running_) {
        std::string script;
        
        {
            std::lock_guard<std::mutex> lock(queue_mutex_);
            if (!script_queue_.empty()) {
                script = std::move(script_queue_.front());
                script_queue_.pop();
            }
        }
        
        if (!script.empty()) {
            if (status_cb_) status_cb_("Executing...");
            
            bool success = lua_engine_.execute(script);
            
            if (success) {
                if (status_cb_) status_cb_("Executed ✓");
            } else {
                if (status_cb_) status_cb_("Error ✗");
            }
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

} // namespace oss