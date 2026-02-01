#include "command.h"
#include "serial_io.h"
#include "crypt.h"
#include "ping.h"
#include <string.h>
#include <esp_log.h>
#include <mbedtls/rsa.h>
#include <mbedtls/sha256.h>
#include <mbedtls/pk.h>

static const char* TAG = "command";

// Structure for pending command verification
typedef struct {
    cmd_packet_t command;
    uint8_t message_hash[32];
    uint32_t timestamp;
    bool pending;
    uint8_t signature[256];  // Full RSA signature
    bool has_signature_part1;
    bool has_signature_part2;
} pending_command_t;

static pending_command_t pending_cmd;
static uint64_t last_sequence = 0;

void command_init()
{
    memset(&pending_cmd, 0, sizeof(pending_cmd));
    pending_cmd.pending = false;
    pending_cmd.has_signature_part1 = false;
    pending_cmd.has_signature_part2 = false;
    last_sequence = 0;
    
    lownet_register_protocol(LOWNET_PROTOCOL_COMMAND, command_receive);
    ESP_LOGI(TAG, "Command protocol initialized");
}

// Compute SHA-256 hash
static void compute_sha256(const uint8_t* data, size_t len, uint8_t* hash)
{
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, data, len);
    mbedtls_sha256_finish(&ctx, hash);
    mbedtls_sha256_free(&ctx);
}

// Verify RSA signature
static bool verify_signature(const uint8_t* message_hash, const uint8_t* signature, const uint8_t* expected_key_hash)
{
    // Verify the public key hash matches our trusted key
    uint8_t trusted_key_hash[32];
    compute_sha256((const uint8_t*)lownet_public_key, strlen(lownet_public_key), trusted_key_hash);
    
    if (memcmp(expected_key_hash, trusted_key_hash, 32) != 0) {
        ESP_LOGE(TAG, "Public key hash mismatch");
        return false;
    }

    // Parse and verify with RSA
    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    
    int ret = mbedtls_pk_parse_public_key(&pk, 
                                         (const unsigned char*)lownet_public_key, 
                                         strlen(lownet_public_key) + 1);
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to parse public key: -0x%04x", -ret);
        mbedtls_pk_free(&pk);
        return false;
    }
    
    // Verify the signature
    ret = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256,
                           message_hash, 32,
                           signature, 256);
    
    mbedtls_pk_free(&pk);
    
    if (ret != 0) {
        ESP_LOGE(TAG, "Signature verification failed: -0x%04x", -ret);
        return false;
    }
    
    ESP_LOGI(TAG, "Signature verified successfully");
    return true;
}

static void process_verified_command(const cmd_packet_t* cmd)
{
    // Extract actual command type (ignore signature bits in upper bits)
    uint8_t command_type = cmd->type & 0x0F;
    
    ESP_LOGI(TAG, "Executing command %u, seq: %llu", command_type, cmd->sequence);
    
    switch (command_type) {
        case 0x01: { // Time command
            lownet_time_t new_time;
            memcpy(&new_time, cmd->contents, sizeof(lownet_time_t));
            lownet_set_time(&new_time);
            
            char time_msg[64];
            snprintf(time_msg, sizeof(time_msg), "Secure time updated: %lu seconds", new_time.seconds);
            serial_write_line(time_msg);
            break;
        }
            
        case 0x02: // Test command
        case 0x04: // Another test command type used by Gróska
        { 
            // These are handled in command_receive with ping responses
            // Just log that we processed it (NO PING HERE - already sent in command_receive)
            ESP_LOGI(TAG, "Test command type %u processed", command_type);
            char test_msg[100];
            snprintf(test_msg, sizeof(test_msg), "Test command type %u processed", command_type);
            serial_write_line(test_msg);
            break;
        }
            
        default:
            ESP_LOGW(TAG, "Unknown command type: %u (raw: %u)", command_type, cmd->type);
            char unknown_msg[50];
            snprintf(unknown_msg, sizeof(unknown_msg), "Unknown command type: %u", command_type);
            serial_write_line(unknown_msg);
            break;
    }
}

static void process_signature_frame(const lownet_frame_t* frame, bool is_part2)
{
    if (!pending_cmd.pending) {
        ESP_LOGW(TAG, "Signature received but no pending command");
        return;
    }
    
    // Check if command is too old (10 second timeout)
    uint32_t current_time = lownet_get_time().seconds;
    if ((current_time - pending_cmd.timestamp) > 10) {
        ESP_LOGW(TAG, "Signature timeout for command %llu", pending_cmd.command.sequence);
        serial_write_line("Command rejected: signature timeout");
        pending_cmd.pending = false;
        return;
    }
    
    const cmd_signature_t* sig = (const cmd_signature_t*)frame->payload;
    
    // Store signature part
    if (is_part2) {
        memcpy(pending_cmd.signature + 128, sig->sig_part, 128);
        pending_cmd.has_signature_part2 = true;
        ESP_LOGI(TAG, "Received signature part 2");
    } else {
        memcpy(pending_cmd.signature, sig->sig_part, 128);
        pending_cmd.has_signature_part1 = true;
        ESP_LOGI(TAG, "Received signature part 1");
    }
    
    // Check if we have both signature parts
    if (pending_cmd.has_signature_part1 && pending_cmd.has_signature_part2) {
        ESP_LOGI(TAG, "Both signature parts received, verifying...");
        
        // Verify the signature
        if (verify_signature(pending_cmd.message_hash, pending_cmd.signature, sig->hash_key)) {
            ESP_LOGI(TAG, "Command %llu verified successfully", pending_cmd.command.sequence);
            serial_write_line("Command accepted: valid signature");
            process_verified_command(&pending_cmd.command);
        } else {
            ESP_LOGE(TAG, "Command %llu signature invalid", pending_cmd.command.sequence);
            serial_write_line("Command rejected: invalid signature");
        }
        
        // Reset pending command
        pending_cmd.pending = false;
        pending_cmd.has_signature_part1 = false;
        pending_cmd.has_signature_part2 = false;
    }
}

void command_receive(const lownet_frame_t* frame)
{
    if (!frame || frame->length < 1) return;

    uint8_t sig_bits = frame->protocol & 0x03;
    ESP_LOGI(TAG, "Command frame, sig_bits: %d, length: %d", sig_bits, frame->length);

    switch (sig_bits) {
        case 0x00: // Unsigned frame (for testing only)
            if (frame->length >= sizeof(cmd_packet_t)) {
                const cmd_packet_t* cmd = (const cmd_packet_t*)frame->payload;
                uint8_t command_type = cmd->type & 0x0F;
                
                ESP_LOGI(TAG, "=== COMMAND FRAME RECEIVED ===");
                ESP_LOGI(TAG, "Source: 0x%02x", frame->source);
                ESP_LOGI(TAG, "Command type: %u (raw: 0x%02x)", command_type, cmd->type);
                ESP_LOGI(TAG, "Sequence: %llu", cmd->sequence);
                ESP_LOGI(TAG, "Frame length: %u", frame->length);
                ESP_LOGI(TAG, "Encryption key set: %s", lownet_get_key() ? "YES" : "NO");
                
                // SEQUENCE CHECK - only process NEW commands
                if (cmd->sequence <= last_sequence) {
                    ESP_LOGW(TAG, "STALE COMMAND - IGNORING (seq: %llu, last: %llu)", 
                             cmd->sequence, last_sequence);
                    ESP_LOGI(TAG, "=== COMMAND IGNORED (STALE) ===");
                    return;
                }
                last_sequence = cmd->sequence;
                
                // For ALL test commands, respond with ping containing the test content
                if (command_type == 0x02 || command_type == 0x04) {
                    ESP_LOGI(TAG, ">>> SENDING PING RESPONSE TO TEST COMMAND TYPE %u", command_type);
                    
                    // Calculate the test content length
                    uint8_t test_content_length = frame->length - sizeof(cmd_packet_t);
                    
                    if (test_content_length > 0) {
                        ESP_LOGI(TAG, "Sending ping with test content, length: %u", test_content_length);
                        // Send ping WITH the test command content as payload
                        ping(frame->source, cmd->contents, test_content_length);
                    } else {
                        ESP_LOGI(TAG, "Sending ping with default response (no test content)");
                        const uint8_t default_response[] = "TEST_RESPONSE";
                        ping(frame->source, default_response, sizeof(default_response) - 1);
                    }
                    
                    ESP_LOGI(TAG, "<<< PING RESPONSE SENT");
                    serial_write_line("Test command acknowledged with ping");
                    
                    // Then process the command normally
                    process_verified_command(cmd);
                } 
                // For time commands, process normally
                else if (command_type == 0x01) {
                    ESP_LOGI(TAG, "Processing TIME command");
                    process_verified_command(cmd);
                }
                // For other commands, just process
                else {
                    ESP_LOGI(TAG, "Processing other command type: %u", command_type);
                    process_verified_command(cmd);
                }
                
                ESP_LOGI(TAG, "=== COMMAND PROCESSING COMPLETE ===");
            }
            break;

        case 0x01: { // Command expecting signature
            if (frame->length >= sizeof(cmd_packet_t)) {
                const cmd_packet_t* cmd = (const cmd_packet_t*)frame->payload;
                
                // Store command for signature verification
                memcpy(&pending_cmd.command, cmd, sizeof(cmd_packet_t));
                compute_sha256(frame->payload, frame->length, pending_cmd.message_hash);
                pending_cmd.timestamp = lownet_get_time().seconds;
                pending_cmd.pending = true;
                pending_cmd.has_signature_part1 = false;
                pending_cmd.has_signature_part2 = false;
                
                ESP_LOGI(TAG, "Command %llu queued for signature", cmd->sequence);
                
                char queue_msg[60];
                snprintf(queue_msg, sizeof(queue_msg), "Command %llu queued, waiting for signature", cmd->sequence);
                serial_write_line(queue_msg);
            }
            break;
        }

        case 0x02: // First signature part
            if (frame->length >= sizeof(cmd_signature_t)) {
                ESP_LOGI(TAG, "Processing signature part 1");
                process_signature_frame(frame, false);
            }
            break;

        case 0x03: // Second signature part  
            if (frame->length >= sizeof(cmd_signature_t)) {
                ESP_LOGI(TAG, "Processing signature part 2");
                process_signature_frame(frame, true);
            }
            break;
    }
}
