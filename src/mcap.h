#pragma once

#include <zephyr/kernel.h>
#include <zephyr/fs/fs.h>

// #define MCAP_ENCODING_

struct mcap_statistics_t {
    uint64_t message_count;
    uint16_t schema_count;
    uint32_t channel_count;
    uint32_t attachment_count;
    uint32_t metadata_count;
    uint32_t chunk_count;
    uint64_t message_start_time;
    uint64_t message_end_time;
    // uint16_t channel_message_counts[];
};

struct mcap_file_t {
    struct fs_file_t* fd;
    uint64_t fd_offset;
    struct mcap_statistics_t statistics;
};

struct mcap_metadata_t {
    uint32_t something;
};

struct mcap_footer_t {
    uint64_t summary_start;
    uint64_t summary_offset_start;
    uint32_t summary_crc;
};

// API
struct mcap_file_t mcap_init(struct fs_file_t* fd);
uint16_t mcap_add_schema(struct mcap_file_t* mcap_file, const char* name, const char* encoding, const uint8_t* schema_buffer, uint32_t schema_len);
uint16_t mcap_add_channel(struct mcap_file_t* mcap_file, uint16_t schema_id, const char* topic, const char* encoding, const struct mcap_metadata_t* metadata);
uint16_t mcap_write_message(struct mcap_file_t* mcap_file, uint16_t channel_id, uint32_t sequence, uint64_t log_time, uint64_t publish_time, const uint8_t* data, uint32_t len);
void mcap_finish(struct mcap_file_t* mcap_file);


uint32_t mcap_write_record_preamble(struct fs_file_t* fd, uint8_t type, uint64_t len);
void mcap_write_header(struct mcap_file_t* mcap_file, const char* profile);
//uint32_t mcap_write_string(int fd, const char * data);
void mcap_write_footer(struct mcap_file_t* mcap_file, struct mcap_footer_t* footer);
