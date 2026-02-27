#include "http.hpp"
#include "logger.hpp"
#include <curl/curl.h>
#include <cstring>

namespace oss {

// ── CURL write callback ──────────────────────────────────────────────

static size_t write_callback(char* ptr, size_t size, size_t nmemb,
                             void* userdata) {
    auto* body = static_cast<std::string*>(userdata);
    size_t total = size * nmemb;
    body->append(ptr, total);
    return total;
}

// ── CURL header callback ─────────────────────────────────────────────

static size_t header_callback(char* buffer, size_t size, size_t nitems,
                              void* userdata) {
    auto* headers = static_cast<std::map<std::string, std::string>*>(userdata);
    size_t total = size * nitems;
    std::string line(buffer, total);

    // Strip trailing \r\n
    while (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
        line.pop_back();

    auto colon = line.find(':');
    if (colon != std::string::npos) {
        std::string key = line.substr(0, colon);
        std::string val = line.substr(colon + 1);
        // Trim leading whitespace from value
        size_t start = val.find_first_not_of(" \t");
        if (start != std::string::npos)
            val = val.substr(start);
        (*headers)[key] = val;
    }

    return total;
}

// ── Singleton ────────────────────────────────────────────────────────

Http& Http::instance() {
    static Http inst;
    return inst;
}

Http::Http() {
    curl_global_init(CURL_GLOBAL_DEFAULT);
}

Http::~Http() {
    curl_global_cleanup();
}

// ── Public API ───────────────────────────────────────────────────────

HttpResponse Http::get(const std::string& url,
                       const std::map<std::string, std::string>& headers) {
    return perform(url, "GET", "", headers);
}

HttpResponse Http::post(const std::string& url,
                        const std::string& body,
                        const std::map<std::string, std::string>& headers) {
    return perform(url, "POST", body, headers);
}

// ── Core request ─────────────────────────────────────────────────────

HttpResponse Http::perform(const std::string& url,
                           const std::string& method,
                           const std::string& body,
                           const std::map<std::string, std::string>& headers) {
    std::lock_guard<std::mutex> lock(mutex_);

    HttpResponse response;

    CURL* curl = curl_easy_init();
    if (!curl) {
        response.error = "Failed to initialize CURL";
        LOG_ERROR("HTTP: {}", response.error);
        return response;
    }

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response.body);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_callback);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &response.headers);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "OSSExecutor/2.0");
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);

    // Max 10 MB response
    curl_easy_setopt(curl, CURLOPT_MAXFILESIZE, 10L * 1024L * 1024L);

    // Set method
    if (method == "POST") {
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE,
                         static_cast<long>(body.size()));
    }

    // Custom headers
    struct curl_slist* header_list = nullptr;
    for (const auto& [key, val] : headers) {
        std::string h = key + ": " + val;
        header_list = curl_slist_append(header_list, h.c_str());
    }
    if (header_list) {
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, header_list);
    }

    // Perform
    CURLcode res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
        response.error = curl_easy_strerror(res);
        response.status_code = 0;
        LOG_ERROR("HTTP {} {} failed: {}", method, url, response.error);
    } else {
        long code = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
        response.status_code = static_cast<int>(code);
        LOG_INFO("HTTP {} {} -> {}", method, url, response.status_code);
    }

    if (header_list) curl_slist_free_all(header_list);
    curl_easy_cleanup(curl);

    return response;
}

} // namespace oss
