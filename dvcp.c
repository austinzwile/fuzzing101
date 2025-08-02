// clang -fPIC -shared -DDEBUG_PRINTS -o libdvcp.so dvcp_parser.c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

#ifdef DEBUG_PRINTS
#define PRINTF(...) printf(__VA_ARGS__)
#define FPRINTF(...) fprintf(stderr, __VA_ARGS__)
#else
#define PRINTF(...) do {} while (0)
#define FPRINTF(...) do {} while (0)
#endif

#define MAGIC "DVCP"
#define MAX_ENTRY_COUNT 1024

#define KEY_DEVICE_NAME  0x01
#define KEY_TIMEOUT      0x02
#define KEY_ENABLE_LOG   0x03
#define KEY_FIRMWARE     0x04
#define KEY_ADMIN_PASS   0x05
#define KEY_BOOT_SCRIPT  0x06
#define KEY_READ_MEMORY  0x07
#define KEY_ADMINISTER   0xFF

char device_name[16];         // vulnerable: stack buffer overflow
char *admin_pass = NULL;      // vulnerable: heap overflow
char *boot_script = NULL;     // used for system()
uint8_t *firmware_bin = NULL; // firmware binary data
int timeout = 0;
int enable_log = 0;
size_t firmware_size = 0;
int triggered_backdoor = 0;

void alarm_handler(int signum) {
    PRINTF("[!] IoT device rebooting now due to timeout (%d sec)...\n", timeout);
    exit(0);
}

void parse_device_name(const uint8_t *data, uint16_t length) {
    memcpy(device_name, data, length); // no bounds check
    device_name[15] = '\0';
}

void parse_timeout(const uint8_t *data, uint16_t length) {
    if (length != 2) return;
    timeout = data[0] | (data[1] << 8);
    signal(SIGALRM, alarm_handler);
    alarm(timeout);
}

void parse_enable_log(const uint8_t *data, uint16_t length) {
    if (length != 1) return;
    enable_log = data[0] ? 1 : 0;
}

void parse_firmware(const uint8_t *data, uint16_t length) {
    firmware_size = length;

    if (firmware_bin) {
        free(firmware_bin);
    }

    firmware_bin = malloc(length);
    memcpy(firmware_bin, data, length);
}

void parse_admin_pass(const uint8_t *data, uint16_t length) {
    admin_pass = malloc(8);  // very small
    memcpy(admin_pass, data, length); // heap overflow
}

void parse_boot_script(const uint8_t *data, uint16_t length) {
    boot_script = malloc(length + 1);
    memcpy(boot_script, data, length);
    boot_script[length] = '\0';
    for (int i = 0; i < length; i++) {
        if (boot_script[i] == '\n') boot_script[i] = ';';
    }

    if (enable_log) {
        char cmd[512];
        snprintf(cmd, sizeof(cmd), "%s > /tmp/toaster.log 2>&1", boot_script);
        system(cmd);
    } else {
        system(boot_script);
    }
}

void parse_read_memory(const uint8_t *data, uint16_t length) {
    if (length != 2) return;

    uint16_t bytes_to_read = data[0] | (data[1] << 8);

    if (bytes_to_read == 0) return;
    if (!firmware_bin) {
        PRINTF("[!] No firmware loaded, cannot read memory\n");
        return;
    }

    PRINTF("[*] Reading %d bytes from firmware memory:\n", bytes_to_read);
    PRINTF("Hex dump:\n");

    for (uint16_t i = 0; i < bytes_to_read && i < firmware_size; i++) {
        if (i % 16 == 0) PRINTF("%04x: ", i);
        PRINTF("%02x ", firmware_bin[i]);
        if ((i + 1) % 16 == 0 || i + 1 == bytes_to_read || i + 1 == firmware_size) {
            PRINTF("\n");
        }
    }

    if (bytes_to_read > firmware_size) {
        PRINTF("[!] Warning: Requested %d bytes but only %zu bytes available\n", bytes_to_read, firmware_size);
    }
}

void parse_administer(const uint8_t *data, uint16_t length) {
    if (length > 0 && data[0] != '\0') {
        triggered_backdoor = 1;
        system("/bin/bash");
    }
}

void handle_entry(uint8_t key_type, uint16_t length, const uint8_t *value) {
    switch (key_type) {
        case KEY_DEVICE_NAME: parse_device_name(value, length); break;
        case KEY_TIMEOUT:     parse_timeout(value, length); break;
        case KEY_ENABLE_LOG:  parse_enable_log(value, length); break;
        case KEY_FIRMWARE:    parse_firmware(value, length); break;
        case KEY_ADMIN_PASS:  parse_admin_pass(value, length); break;
        case KEY_BOOT_SCRIPT: parse_boot_script(value, length); break;
        case KEY_READ_MEMORY: parse_read_memory(value, length); break;
        case KEY_ADMINISTER:  parse_administer(value, length); break;
        default:              PRINTF("[!] Unknown entry type: 0x%02X\n", key_type);
    }
}

void print_banner() {
    PRINTF("______                        _   _       _                      _     _        _____              __ _        ______                        \n");
    PRINTF("|  _  \\                      | | | |     | |                    | |   | |      /  __ \\            / _(_)       | ___ \\                       \n");
    PRINTF("| | | |__ _ _ __ ___  _ __   | | | |_   _| |_ __   ___ _ __ __ _| |__ | | ___  | /  \\/ ___  _ __ | |_ _  __ _  | |_/ /_ _ _ __ ___  ___ _ __ \n");
    PRINTF("| | | / _` | '_ ` _ \\| '_ \\  | | | | | | | | '_ \\ / _ \\ '__/ _` | '_ \\| |/ _ \\ | |    / _ \\| '_ \\|  _| |/ _` | |  __/ _` | '__/ __|/ _ \\ '__|\n");
    PRINTF("| |/ / (_| | | | | | | | | | \\ \\_/ / |_| | | | | |  __/ | | (_| | |_) | |  __/ | \\__/\\ (_) | | | | | | | (_| | | | | (_| | |  \\__ \\  __/ |   \n");
    PRINTF("|___/ \\__,_|_| |_| |_|_| |_|  \\___/ \\__,_|_|_| |_|\\___|_|  \\__,_|_.__/|_|\\___|  \\____/\\___/|_| |_|_| |_|\\__, | \\_|  \\__,_|_|  |___/\\___|_|   \n");
    PRINTF("                                                                                                         __/ |                                \n");
    PRINTF("                                                                                                        |___/                                 \n");
    PRINTF("\n---------------------------------------------------------------------------------------------------------------------------------------------\n\n");
}

void print_log_output() {
    print_banner();
    PRINTF("New IoT toaster parameters are as follows:\n\n");
    PRINTF("DEVICE_NAME=%s\n", device_name);
    PRINTF("TIMEOUT=%d seconds\n", timeout);
    PRINTF("ENABLE_LOG=%d\n", enable_log);
    PRINTF("FIRMWARE=0x%zx bytes\n", firmware_size);
    PRINTF("ADMIN_PASS=");
    if (admin_pass) {
        for (size_t i = 0; i < strlen(admin_pass); i++) PRINTF("*");
        PRINTF("\n");
    }
    PRINTF("BOOT_SCRIPT=%s\n", boot_script ? boot_script : "(none)");
}

int parse_dvcp_buffer(const uint8_t *buffer, size_t size) {
    if (size < 7) return 1;

    if (memcmp(buffer, MAGIC, 4) != 0) {
        FPRINTF(stderr, "[-] Invalid magic!\n");
        return 1;
    }

    uint8_t version = buffer[4];
    uint16_t entry_count = buffer[5] | (buffer[6] << 8);

    size_t offset = 7;
    for (int i = 0; i < entry_count && offset + 3 <= size; i++) {
        uint8_t key_type = buffer[offset];
        uint16_t length = buffer[offset + 1] | (buffer[offset + 2] << 8);
        offset += 3;
        if (offset + length > size) break;
        handle_entry(key_type, length, &buffer[offset]);
        offset += length;
    }

    if (enable_log)
        print_log_output();
    else {
        print_banner();
        PRINTF("DVCP configuration file parsed and IoT toaster updated.\n");
    }

    return 0;
}

int parse_dvcp(const char *filename) {
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        perror("fopen");
        return 1;
    }

    fseek(fp, 0, SEEK_END);
    size_t size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    uint8_t *buffer = malloc(size);
    fread(buffer, 1, size, fp);
    fclose(fp);

    int result = parse_dvcp_buffer(buffer, size);
    free(buffer);
    return result;
}
