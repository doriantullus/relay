/* Single translate-c root for all vendored C APIs (libssh2 + LibreSSL).
 * Imported as module "c" — see build.zig. */
#include <libssh2.h>
#include <libssh2_sftp.h>
#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
