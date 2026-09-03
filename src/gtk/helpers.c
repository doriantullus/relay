#include <gtk/gtk.h>

void relay_gtk_set_accels(
    GtkApplication *application,
    const char *action,
    const char *first,
    const char *second
) {
    const char *accelerators[] = { first, second, NULL };
    gtk_application_set_accels_for_action(application, action, accelerators);
}

void relay_gtk_accessible_label(GtkWidget *widget, const char *label) {
    gtk_accessible_update_property(
        GTK_ACCESSIBLE(widget),
        GTK_ACCESSIBLE_PROPERTY_LABEL,
        label,
        -1
    );
}
