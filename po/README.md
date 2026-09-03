# Localization

Linux user-visible strings are listed in `POTFILES.in`. GTK strings currently
live in `src/gtk/application.zig`; keep new text centralized and avoid building
sentences from independently translated fragments. The desktop and AppStream
files use the standard translatable-key formats consumed by gettext tooling.
