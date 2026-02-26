#include "file_dialog.hpp"

namespace oss {

void FileDialog::open(GtkWindow* parent, Callback cb) {
    GtkFileDialog* dialog = gtk_file_dialog_new();
    gtk_file_dialog_set_title(dialog, "Open Script");
    
    // Add Lua filter
    GListStore* filters = g_list_store_new(GTK_TYPE_FILE_FILTER);
    
    GtkFileFilter* lua_filter = gtk_file_filter_new();
    gtk_file_filter_set_name(lua_filter, "Lua Scripts (*.lua, *.luau, *.txt)");
    gtk_file_filter_add_pattern(lua_filter, "*.lua");
    gtk_file_filter_add_pattern(lua_filter, "*.luau");
    gtk_file_filter_add_pattern(lua_filter, "*.txt");
    g_list_store_append(filters, lua_filter);
    g_object_unref(lua_filter);
    
    GtkFileFilter* all_filter = gtk_file_filter_new();
    gtk_file_filter_set_name(all_filter, "All Files");
    gtk_file_filter_add_pattern(all_filter, "*");
    g_list_store_append(filters, all_filter);
    g_object_unref(all_filter);
    
    gtk_file_dialog_set_filters(dialog, G_LIST_MODEL(filters));
    g_object_unref(filters);
    
    auto* cb_ptr = new Callback(std::move(cb));
    
    gtk_file_dialog_open(dialog, parent, nullptr,
        [](GObject* source, GAsyncResult* result, gpointer user_data) {
            auto* callback = static_cast<Callback*>(user_data);
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
            
            if (error) g_error_free(error);
            delete callback;
        }, cb_ptr);
    
    g_object_unref(dialog);
}

void FileDialog::save(GtkWindow* parent, const std::string& suggested_name, Callback cb) {
    GtkFileDialog* dialog = gtk_file_dialog_new();
    gtk_file_dialog_set_title(dialog, "Save Script");
    gtk_file_dialog_set_initial_name(dialog, suggested_name.c_str());
    
    auto* cb_ptr = new Callback(std::move(cb));
    
    gtk_file_dialog_save(dialog, parent, nullptr,
        [](GObject* source, GAsyncResult* result, gpointer user_data) {
            auto* callback = static_cast<Callback*>(user_data);
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
            
            if (error) g_error_free(error);
            delete callback;
        }, cb_ptr);
    
    g_object_unref(dialog);
}

} // namespace oss