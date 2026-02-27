#include "http.hpp"
#include "logger.hpp"
#include <curl/curl.h>
#include <stdexcept>

namespace oss {

Http::Http() {
    curl_global_init(CURL_GLOBAL_DEFAULT);
}

Http::~Http() {
    curl_global_cleanup();
}

Http& Http::instance() {
    static Http inst;
    return inst;
}

size_t Http::write_callback(void* contents, size_t size,
                            size_t nmemb, void* userp) {
    size_t total = size * nmemb;
    static_cast<std::string*>(userp)->append(
        static_cast<char*>(contents), total);
    return total;
}

HttpResponse Http::get(const std::string& url) {
    std::lock_guard<std::mutex> lock(request_mutex_);

    HttpResponse response;

    CURL* curl = curl_easy_init();
    if (!curl) {
        LOG_ERROR("Http::get — failed to init cURL");
        response.status_code = -1;
        response.body = "Failed to initialize cURL";
        return response;
    }

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response.body);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "OSS-Executor/1.0");

    // Collect headers
    struct curl_slist* req_headers = nullptr;
    req_headers = curl_slist_append(req_headers,
        "Accept: */*");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, req_headers);

    // Response header callback
    std::string raw_headers;
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &raw_headers);

    CURLcode res = curl_easy_perform(curl);
    curl_slist_free_all(req_headers);

    if (res != CURLE_OK) {
        std::string err = curl_easy_strerror(res);
        LOG_ERROR("Http::get '{}' failed: {}", url, err);
        curl_easy_cleanup(curl);
        response.status_code = -1;
        response.body = "HTTP GET failed: " + err;
        return response;
    }

    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    response.status_code = static_cast<int>(http_code);

    curl_easy_cleanup(curl);

    // Parse raw headers into map
    std::istringstream hstream(raw_headers);
    std::string line;
    while (std::getline(hstream, line)) {
        // Remove \r
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        auto colon = line.find(':');
        if (colon != std::string::npos) {
            std::string key = line.substr(0, colon);
            std::string val = line.substr(colon + 1);
            // Trim leading space
            if (!val.empty() && val[0] == ' ')
                val = val.substr(1);
            response.headers[key] = val;
        }
    }

    LOG_INFO("Http::get '{}' → {} bytes, status {}",
             url, response.body.size(), response.status_code);

    return response;
}

HttpResponse Http::post(const std::string& url,
                        const std::string& body,
                        const std::string& content_type) {
    std::lock_guard<std::mutex> lock(request_mutex_);

    HttpResponse response;

    CURL* curl = curl_easy_init();
    if (!curl) {
        response.status_code = -1;
        response.body = "Failed to initialize cURL";
        return response;
    }

    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers,
        ("Content-Type: " + content_type).c_str());

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE,
                     static_cast<long>(body.size()));
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response.body);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "OSS-Executor/1.0");

    CURLcode res = curl_easy_perform(curl);
    curl_slist_free_all(headers);

    if (res != CURLE_OK) {
        std::string err = curl_easy_strerror(res);
        curl_easy_cleanup(curl);
        response.status_code = -1;
        response.body = "HTTP POST failed: " + err;
        return response;
    }

    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    response.status_code = static_cast<int>(http_code);

    curl_easy_cleanup(curl);

    LOG_INFO("Http::post '{}' → {} bytes, status {}",
             url, response.body.size(), response.status_code);

    return response;
}

} // namespace oss
