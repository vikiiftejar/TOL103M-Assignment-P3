#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <esp_log.h>

#include "ping.h"

#include "serial_io.h"
#include "utility.h"

#define TAG "PING"

void ping_init()
{
	if (lownet_register_protocol(LOWNET_PROTOCOL_PING, ping_receive) != 0)
		{
			ESP_LOGE(TAG, "Error registering PING protocol");
		}
}

void ping_command(char* args)
{
	if (!args)
		{
			serial_write_line("A node id must be provided\n");
			return;
		}

	uint8_t dest = (uint8_t) hex_to_dec(args + 2);
	if (dest == 0)
		{
			serial_write_line("Invalid node id\n");
			return;
		}

	ping(dest, NULL, 0);
}

void ping(uint8_t node, const uint8_t* payload, uint8_t length)
{
    ESP_LOGI("PING", ">>> SENDING PING to node 0x%02x", node);
    ESP_LOGI("PING", "Encryption: %s", lownet_get_key() ? "ENABLED" : "DISABLED");
    ESP_LOGI("PING", "Payload length: %u", length);
    
    if (payload && length > 0) {
        ESP_LOGI("PING", "Payload content: %.*s", length, payload);
    }
    
    lownet_frame_t frame;
    frame.source = lownet_get_device_id();
    frame.destination = node;
    frame.protocol = LOWNET_PROTOCOL_PING;
    frame.length = sizeof(ping_packet_t);

    ping_packet_t packet;
    packet.timestamp_out = lownet_get_time();
    packet.origin = lownet_get_device_id();

    memcpy(&frame.payload, &packet, sizeof packet);

    if (payload)
    {
        memcpy(frame.payload + frame.length,
                 payload,
                 min(LOWNET_PAYLOAD_SIZE - sizeof(ping_packet_t), length));
        frame.length += min(LOWNET_PAYLOAD_SIZE - sizeof(ping_packet_t), length);
    }

    lownet_send(&frame);
    
    ESP_LOGI("PING", "<<< PING SENT to node 0x%02x", node);
}

void ping_receive(const lownet_frame_t* frame)
{
    ESP_LOGI("PING", "PING frame received from 0x%02x, length: %u", frame->source, frame->length);
    
    if (frame->length < sizeof(ping_packet_t))
    {
        ESP_LOGW("PING", "Malformed ping frame - too short");
        return;
    }

    ping_packet_t packet;
    memcpy(&packet, &frame->payload, sizeof packet);

    if (packet.origin == lownet_get_device_id())
    {
        ESP_LOGI("PING", "PING RESPONSE received from 0x%02x", frame->source);
        lownet_time_t now = lownet_get_time();
        lownet_time_t rtt = time_diff(&packet.timestamp_out, &now);

        // reply from + id + rtt: + time + null
        char buffer[12 + ID_WIDTH + 6 + TIME_WIDTH + 1];
        int n = 0;
        n += sprintf(buffer + n, "Reply from: ");
        n += format_id(buffer + n, frame->source);
        n += sprintf(buffer + n, " RTT: ");
        n += format_time(buffer + n, &rtt);
        serial_write_line(buffer);
    }
    else
    {
        ESP_LOGI("PING", "PING REQUEST received from 0x%02x - sending response", frame->source);
        packet.timestamp_back = lownet_get_time();

        lownet_frame_t reply;
        reply.source = lownet_get_device_id();
        reply.destination = frame->source;
        reply.protocol = LOWNET_PROTOCOL_PING;
        reply.length = frame->length;

        memcpy(&reply.payload, &frame->payload, frame->length);
        memcpy(&reply.payload, &packet, sizeof packet);

        lownet_send(&reply);
        ESP_LOGI("PING", "PING RESPONSE sent to 0x%02x", frame->source);
    }
}
