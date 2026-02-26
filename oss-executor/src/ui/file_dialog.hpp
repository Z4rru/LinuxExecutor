#pragma once

#include <gtk/gtk.h>
#include <string>
#include <functional>

namespace oss {

class FileDialog {
public:
    using Callback = std::function<void(const std::string& path)>;

    static void open(GtkWindow* parent, Callback cb);
    static void save(GtkWindow* parent, const std::string& suggested_name, Callback cb);
};

} // namespace oss