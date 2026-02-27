#pragma once

#include <string>
#include <functional>
#include <future>
#include <curl/curl.h>
#include <memory>
#include <map>

namespace oss {

struct HttpResponse {
    long status_code = 0;
    std::string body;
    std::map<std::string, std::string> headers;
    std::string error;
    bool success() const { return status_code >= 200 && status_code < 300; }
};

class Http {
public:
    static Http& instance() {
        static Http inst;
        return inst;
    }

    HttpResponse get(const std::string& url,
                     const std::map<std::string, std::string>& headers = {}) {
        return request("GET", url, "", headers);
    }

    HttpResponse post(const std::string& url, const std::string& body,
                      const std::map<std::string, std::string>& headers = {}) {
        return request("POST", url, body, headers);
    }

    std::future<HttpResponse> get_async(const std::string& url,
                                        const std::map<std::string, std::string>& headers = {}) {
        return std::async(std::launch::async, [this, url, headers]() {
            return get(url, headers);
        });
    }

    std::future<HttpResponse> post_async(const std::string& url, const std::string& body,
                                         const std::map<std::string, std::string>& headers = {}) {
        return std::async(std::launch::async, [this, url, body, headers]() {
            return post(url, body, headers);
        });
    }

private:
    Http() { curl_global_init(CURL_GLOBAL_ALL); }
    ~Http() { curl_global_cleanup(); }
    Http(const Http&) = delete;
    Http& operator=(const Http&) = delete;

    static size_t write_callback(char* data, size_t size, size_t nmemb, void* userp) {
        auto* response = static_cast<std::string*>(userp);
        response->append(data, size * nmemb);
        return size * nmemb;
    }

    static size_t header_callback(char* data, size_t size, size_t nmemb, void* userp) {
        auto* headers = static_cast<std::map<std::string, std::string>*>(userp);
        std::string line(data, size * nmemb);
        auto colon = line.find(':');
        if (colon != std::string::npos) {
            std::string key = line.substr(0, colon);
            std::string val = (colon + 2 < line.size()) ? line.substr(colon + 2) : "";
            while (!val.empty() && (val.back() == '\r' || val.back() == '\n'))
                val.pop_back();
            (*headers)[key] = val;
        }
        return size * nmemb;
    }

    HttpResponse request(const std::string& method, const std::string& url,
                         const std::string& body,
                         const std::map<std::string, std::string>& headers) {
        HttpResponse response;

        auto curl = std::unique_ptr<CURL, decltype(&curl_easy_cleanup)>(
            curl_easy_init(), curl_easy_cleanup);

        if (!curl) {
            response.error = "Failed to init CURL";
            return response;
        }

        curl_easy_setopt(curl.get(), CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl.get(), CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl.get(), CURLOPT_WRITEDATA, &response.body);
        curl_easy_setopt(curl.get(), CURLOPT_HEADERFUNCTION, header_callback);
        curl_easy_setopt(curl.get(), CURLOPT_HEADERDATA, &response.headers);
        curl_easy_setopt(curl.get(), CURLOPT_TIMEOUT, 30L);
        curl_easy_setopt(curl.get(), CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curl.get(), CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(curl.get(), CURLOPT_USERAGENT, "OSSExecutor/2.0");

        // RAII wrapper — auto-cleans even if an exception is thrown
        struct SlistDeleter {
            void operator()(curl_slist* p) { if (p) curl_slist_free_all(p); }
        };
        std::unique_ptr<curl_slist, SlistDeleter> header_list;
        for (const auto& [key, val] : headers) {
            header_list.reset(
                curl_slist_append(header_list.release(),
                    (key + ": " + val).c_str()));
        }
        if (header_list) {
            curl_easy_setopt(curl.get(), CURLOPT_HTTPHEADER, header_list.get());
        }

        if (method == "POST") {
            curl_easy_setopt(curl.get(), CURLOPT_POSTFIELDS, body.c_str());
            curl_easy_setopt(curl.get(), CURLOPT_POSTFIELDSIZE,
                             static_cast<long>(body.size()));
        }

        CURLcode res = curl_easy_perform(curl.get());

        if (res != CURLE_OK) {
            response.error = curl_easy_strerror(res);
        } else {
            curl_easy_getinfo(curl.get(), CURLINFO_RESPONSE_CODE,
                              &response.status_code);
        }

        // header_list auto-freed here by unique_ptr destructor

        return response;
    }
};

} // namespace oss
