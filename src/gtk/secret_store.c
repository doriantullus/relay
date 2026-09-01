#include <libsecret/secret.h>
#include <gio/gio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

enum relay_secret_result {
    RELAY_SECRET_OK = 0,
    RELAY_SECRET_NOT_FOUND = 1,
    RELAY_SECRET_ACCESS_DENIED = 2,
    RELAY_SECRET_UNEXPECTED = 3,
};

static const SecretSchema relay_schema = {
    "us.doriantull.relay.credentials",
    SECRET_SCHEMA_NONE,
    {
        { "protocol", SECRET_SCHEMA_ATTRIBUTE_STRING },
        { "host", SECRET_SCHEMA_ATTRIBUTE_STRING },
        { "port", SECRET_SCHEMA_ATTRIBUTE_STRING },
        { "account", SECRET_SCHEMA_ATTRIBUTE_STRING },
        { NULL, 0 },
    },
};

static enum relay_secret_result relay_error_result(GError *error, char **message_out) {
    if (message_out != NULL) {
        *message_out = g_strdup(error != NULL && error->message != NULL
            ? error->message
            : "Secret Service request failed");
    }
    enum relay_secret_result result = RELAY_SECRET_UNEXPECTED;
    if (error != NULL && (
        g_error_matches(error, SECRET_ERROR, SECRET_ERROR_IS_LOCKED) ||
        g_error_matches(error, G_IO_ERROR, G_IO_ERROR_PERMISSION_DENIED) ||
        g_error_matches(error, G_DBUS_ERROR, G_DBUS_ERROR_ACCESS_DENIED) ||
        g_error_matches(error, G_DBUS_ERROR, G_DBUS_ERROR_AUTH_FAILED)
    )) {
        result = RELAY_SECRET_ACCESS_DENIED;
    }
    if (error != NULL) g_error_free(error);
    return result;
}

static char *relay_dupe(const uint8_t *bytes, size_t len) {
    if (memchr(bytes, '\0', len) != NULL) return NULL;
    return g_strndup((const char *)bytes, len);
}

int relay_secret_lookup(
    const uint8_t *protocol, size_t protocol_len,
    const uint8_t *host, size_t host_len,
    uint16_t port,
    const uint8_t *account, size_t account_len,
    char **secret_out, size_t *secret_len_out, char **message_out
) {
    GError *error = NULL;
    char *protocol_z = relay_dupe(protocol, protocol_len);
    char *host_z = relay_dupe(host, host_len);
    char *account_z = relay_dupe(account, account_len);
    char port_z[6];
    g_snprintf(port_z, sizeof(port_z), "%u", (unsigned)port);
    if (protocol_z == NULL || host_z == NULL || account_z == NULL) {
        g_free(protocol_z); g_free(host_z); g_free(account_z);
        return RELAY_SECRET_UNEXPECTED;
    }
    char *secret = secret_password_lookup_sync(
        &relay_schema, NULL, &error,
        "protocol", protocol_z,
        "host", host_z,
        "port", port_z,
        "account", account_z,
        NULL
    );
    g_free(protocol_z); g_free(host_z); g_free(account_z);
    if (error != NULL) return relay_error_result(error, message_out);
    if (secret == NULL) return RELAY_SECRET_NOT_FOUND;
    *secret_out = secret;
    *secret_len_out = strlen(secret);
    return RELAY_SECRET_OK;
}

int relay_secret_store(
    const uint8_t *protocol, size_t protocol_len,
    const uint8_t *host, size_t host_len,
    uint16_t port,
    const uint8_t *account, size_t account_len,
    const uint8_t *secret, size_t secret_len,
    char **message_out
) {
    GError *error = NULL;
    char *protocol_z = relay_dupe(protocol, protocol_len);
    char *host_z = relay_dupe(host, host_len);
    char *account_z = relay_dupe(account, account_len);
    char *secret_z = relay_dupe(secret, secret_len);
    char port_z[6];
    g_snprintf(port_z, sizeof(port_z), "%u", (unsigned)port);
    if (protocol_z == NULL || host_z == NULL || account_z == NULL || secret_z == NULL) {
        g_free(protocol_z); g_free(host_z); g_free(account_z); g_free(secret_z);
        return RELAY_SECRET_UNEXPECTED;
    }
    gboolean ok = secret_password_store_sync(
        &relay_schema, SECRET_COLLECTION_DEFAULT, "Relay server password",
        secret_z, NULL, &error,
        "protocol", protocol_z,
        "host", host_z,
        "port", port_z,
        "account", account_z,
        NULL
    );
    secret_password_wipe(secret_z);
    g_free(secret_z);
    g_free(protocol_z); g_free(host_z); g_free(account_z);
    if (error != NULL) return relay_error_result(error, message_out);
    if (!ok) return RELAY_SECRET_UNEXPECTED;
    return RELAY_SECRET_OK;
}

int relay_secret_clear(
    const uint8_t *protocol, size_t protocol_len,
    const uint8_t *host, size_t host_len,
    uint16_t port,
    const uint8_t *account, size_t account_len,
    char **message_out
) {
    GError *error = NULL;
    char *protocol_z = relay_dupe(protocol, protocol_len);
    char *host_z = relay_dupe(host, host_len);
    char *account_z = relay_dupe(account, account_len);
    char port_z[6];
    g_snprintf(port_z, sizeof(port_z), "%u", (unsigned)port);
    if (protocol_z == NULL || host_z == NULL || account_z == NULL) {
        g_free(protocol_z); g_free(host_z); g_free(account_z);
        return RELAY_SECRET_UNEXPECTED;
    }
    gboolean ok = secret_password_clear_sync(
        &relay_schema, NULL, &error,
        "protocol", protocol_z,
        "host", host_z,
        "port", port_z,
        "account", account_z,
        NULL
    );
    g_free(protocol_z); g_free(host_z); g_free(account_z);
    if (error != NULL) return relay_error_result(error, message_out);
    if (!ok) return RELAY_SECRET_NOT_FOUND;
    return RELAY_SECRET_OK;
}

void relay_secret_password_free(char *secret) {
    secret_password_free(secret);
}

void relay_secret_message_free(char *message) {
    g_free(message);
}
