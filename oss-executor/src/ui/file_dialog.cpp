#include "file_dialog.hpp"
#include "utils/logger.hpp"
#include "utils/config.hpp"

namespace oss {

#if GTK_CHECK_VERSION(4, 10, 0)

static void on_open_finish(GObject* source, GAsyncResult* result, gpointer user_data) {
    auto* callback = static_cast<FileDialog::Callback*>(user_data);
    GError* error = nullptr;
    GFile* file = gtk_file_dialog_open_finish(GTK_FILE_DIALOG(source), result, &error);
    if (file) {
        char* path = g_file_get_path(file);
        if (path) {
            (*callback)(path);
            g_free(path);
        }
        g_object_unref(file);
    }
    if (error) {
        if (!g_error_matches(error, GTK_DIALOG_ERROR, GTK_DIALOG_ERROR_DISMISSED)) {
            LOG_ERROR("File dialog error: {}", error->message);
        }
        g_error_free(error);
    }
    delete callback;
}

void FileDialog::open(GtkWindow* parent, Callback cb) {
    GtkFileDialog* dialog = gtk_file_dialog_new();
    gtk_file_dialog_set_title(dialog, "Open Script");

    GtkFileFilter* lua_filter = gtk_file_filter_new();
    gtk_file_filter_set_name(lua_filter, "Lua Scripts (*.lua, *.luau, *.txt)");
    gtk_file_filter_add_pattern(lua_filter, "*.lua");
    gtk_file_filter_add_pattern(lua_filter, "*.luau");
    gtk_file_filter_add_pattern(lua_filter, "*.txt");

    GtkFileFilter* all_filter = gtk_file_filter_new();
    gtk_file_filter_set_name(all_filter, "All Files");
    gtk_file_filter_add_pattern(all_filter, "*");

    GListStore* filters = g_list_store_new(GTK_TYPE_FILE_FILTER);
    g_list_store_append(filters, lua_filter);
    g_list_store_append(filters, all_filter);
    g_object_unref(lua_filter);
    g_object_unref(all_filter);

    gtk_file_dialog_set_filters(dialog, G_LIST_MODEL(filters));
    g_object_unref(filters);

    std::string workspace = Config::instance().home_dir() + "/workspace";
    GFile* initial_dir = g_file_new_for_path(workspace.c_str());
    gtk_file_dialog_set_initial_folder(dialog, initial_dir);
    g_object_unref(initial_dir);

    auto* cb_ptr = new Callback(std::move(cb));
    gtk_file_dialog_open(dialog, parent, nullptr, on_open_finish, cb_ptr);
}

static void on_save_finish(GObject* source, GAsyncResult* result, gpointer user_data) {
    auto* callback = static_cast<FileDialog::Callback*>(user_data);
    GError* error = nullptr;
    GFile* file = gtk_file_dialog_save_finish(GTK_FILE_DIALOG(source), result, &error);
    if (file) {
        char* path = g_file_get_path(file);
        if (path) {
            (*callback)(path);
            g_free(path);
        }
        g_object_unref(file);
    }
    if (error) {
        if (!g_error_matches(error, GTK_DIALOG_ERROR, GTK_DIALOG_ERROR_DISMISSED)) {
            LOG_ERROR("File save dialog error: {}", error->message);
        }
        g_error_free(error);
    }
    delete callback;
}

void FileDialog::save(GtkWindow* parent, const std::string& suggested_name, Callback cb) {
    GtkFileDialog* dialog = gtk_file_dialog_new();
    gtk_file_dialog_set_title(dialog, "Save Script");
    gtk_file_dialog_set_initial_name(dialog, suggested_name.c_str());

    std::string workspace = Config::instance().home_dir() + "/workspace";
    GFile* initial_dir = g_file_new_for_path(workspace.c_str());
    gtk_file_dialog_set_initial_folder(dialog, initial_dir);
    g_object_unref(initial_dir);

    auto* cb_ptr = new Callback(std::move(cb));
    gtk_file_dialog_save(dialog, parent, nullptr, on_save_finish, cb_ptr);
}

#else

static void on_open_response(GtkNativeDialog* dialog, int response, gpointer user_data) {
    auto* callback = static_cast<FileDialog::Callback*>(user_data);
    if (response == GTK_RESPONSE_ACCEPT) {
        GFile* file = gtk_file_chooser_get_file(GTK_FILE_CHOOSER(dialog));
        if (file) {
            char* path = g_file_get_path(file);
            if (path) {
                (*callback)(path);
                g_free(path);
            }
            g_object_unref(file);
        }
    }
    delete callback;
    g_object_unref(dialog);
}

void FileDialog::open(GtkWindow* parent, Callback cb) {
    GtkFileChooserNative* dialog = gtk_file_chooser_native_new(
        "Open Script", parent, GTK_FILE_CHOOSER_ACTION_OPEN, "_Open", "_Cancel");

    GtkFileFilter* lua_filter = gtk_file_filter_new();
    gtk_file_filter_set_name(lua_filter, "Lua Scripts (*.lua, *.luau, *.txt)");
    gtk_file_filter_add_pattern(lua_filter, "*.lua");
    gtk_file_filter_add_pattern(lua_filter, "*.luau");
    gtk_file_filter_add_pattern(lua_filter, "*.txt");
    gtk_file_chooser_add_filter(GTK_FILE_CHOOSER(dialog), lua_filter);

    GtkFileFilter* all_filter = gtk_file_filter_new();
    gtk_file_filter_set_name(all_filter, "All Files");
    gtk_file_filter_add_pattern(all_filter, "*");
    gtk_file_chooser_add_filter(GTK_FILE_CHOOSER(dialog), all_filter);

    auto* cb_ptr = new Callback(std::move(cb));
    g_signal_connect(dialog, "response", G_CALLBACK(on_open_response), cb_ptr);
    gtk_native_dialog_show(GTK_NATIVE_DIALOG(dialog));
}

static void on_save_response(GtkNativeDialog* dialog, int response, gpointer user_data) {
    auto* callback = static_cast<FileDialog::Callback*>(user_data);
    if (response == GTK_RESPONSE_ACCEPT) {
        GFile* file = gtk_file_chooser_get_file(GTK_FILE_CHOOSER(dialog));
        if (file) {
            char* path = g_file_get_path(file);
            if (path) {
                (*callback)(path);
                g_free(path);
            }
            g_object_unref(file);
        }
    }
    delete callback;
    g_object_unref(dialog);
}

void FileDialog::save(GtkWindow* parent, const std::string& suggested_name, Callback cb) {
    GtkFileChooserNative* dialog = gtk_file_chooser_native_new(
        "Save Script", parent, GTK_FILE_CHOOSER_ACTION_SAVE, "_Save", "_Cancel");

    gtk_file_chooser_set_current_name(GTK_FILE_CHOOSER(dialog), suggested_name.c_str());

    auto* cb_ptr = new Callback(std::move(cb));
    g_signal_connect(dialog, "response", G_CALLBACK(on_save_response), cb_ptr);
    gtk_native_dialog_show(GTK_NATIVE_DIALOG(dialog));
}

#endif

} // namespace oss
