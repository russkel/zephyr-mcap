#include "mcap.h"

#include <zephyr/sys/byteorder.h>
#include <zephyr/logging/log.h>
#include <string.h>

const uint8_t MCAP_MAGIC[] = {0x89, 'M', 'C', 'A', 'P', 0x30, 0x1A, 0x0A};
const char MCAP_LIBRARY[] = "zephyr-mcap";

#define MCAP_TYPE_HEADER 0x01
#define MCAP_TYPE_FOOTER 0x02
#define MCAP_TYPE_SCHEMA 0x03
#define MCAP_TYPE_CHANNEL 0x04
#define MCAP_TYPE_MESSAGE 0x05
#define MCAP_TYPE_CHUNK 0x06
#define MCAP_TYPE_MESSAGE_INDEX 0x07
#define MCAP_TYPE_CHUNK_INDEX 0x08
#define MCAP_TYPE_ATTACHMENT 0x09
#define MCAP_TYPE_METADATA 0x0C
#define MCAP_TYPE_DATA_END 0x0F
#define MCAP_TYPE_ATTACHMENT_INDEX 0x0A
#define MCAP_TYPE_METADATA_INDEX 0x0D
#define MCAP_TYPE_STATISTICS 0x0B
#define MCAP_TYPE_SUMMARY_OFFSET 0x0E

LOG_MODULE_REGISTER(mcap_sample, CONFIG_MCAP_SAMPLE_LOG_LEVEL);


void example_mcap_stream() {
    struct fs_file_t file;
    int rc;

    fs_file_t_init(&file);
    char* fname = "test.mcap";
    rc = fs_open(&file, fname, FS_O_CREATE | FS_O_WRITE);
    if (rc < 0) {
        LOG_ERR("FAIL: open %s: %d", fname, rc);
//        return rc;
    }

//    LOG_PRINTK("%s write new boot count %u: [wr:%d]\n", fname,
//               boot_count, rc);

    struct mcap_file_t mcap_file = mcap_init(&file);
    
    uint16_t schema_id = mcap_add_schema(&mcap_file, "sensor_data", "text", NULL, 0);

    struct mcap_metadata_t chan1_metadata;
//    = {
//        {"key1", "value1"},
//        {"key2", "value2"}
//    };

    uint16_t chan1 = mcap_add_channel(&mcap_file, schema_id,
                                      "channel1", "nmea0183", &chan1_metadata);

    char msg_data_buffer[] = "Hello, World! XX";

    for (uint32_t i = 0; i < 10; i++) {
        uint64_t timestamp = 1000 * i;

        msg_data_buffer[14] = '0' + i / 10;
        msg_data_buffer[15] = '0' + i % 10;
        mcap_write_message(&mcap_file, chan1, i,
                           timestamp, timestamp, msg_data_buffer, sizeof(msg_data_buffer));
    }

    mcap_finish(&mcap_file);
    fs_close(&file);
}

uint32_t mcap_string_length(const char* str) {
    return strlen(str) + sizeof(uint32_t);
}

struct mcap_file_t mcap_init(struct fs_file_t* fd) {
    struct mcap_file_t mcap_file = {
            .fd = fd,
            .fd_offset = 0,
            .statistics = {
                    .message_count = 0,
                    .schema_count = 0,
                    .channel_count = 0,
                    .attachment_count = 0,
                    .metadata_count = 0,
                    .chunk_count = 0,
                    .message_start_time = 0,
                    .message_end_time = 0
            }
    };

    fs_write(fd, MCAP_MAGIC, sizeof(MCAP_MAGIC));
    mcap_write_header(&mcap_file, "data_log");
    return mcap_file;
}

uint8_t mcap_write_2bytes(struct fs_file_t* fd, uint16_t data) {
    ssize_t rc;
    data = sys_cpu_to_le16(data);
    rc = fs_write(fd, &data, sizeof(data));

//    if (rc < 0) {
//        LOG_ERR("FAIL: write %s: %d", fname, rc);
//    }
    return sizeof(data);
}

uint8_t mcap_write_4bytes(struct fs_file_t* fd, uint32_t data) {
    ssize_t rc;
    data = sys_cpu_to_le32(data);
    rc = fs_write(fd, &data, sizeof(data));

//    if (rc < 0) {
//        LOG_ERR("FAIL: write %s: %d", fname, rc);
//    }
    return sizeof(data);
}

uint8_t mcap_write_8bytes(struct fs_file_t* fd, uint64_t data) {
    ssize_t rc;
    data = sys_cpu_to_le64(data);
    rc = fs_write(fd, &data, sizeof(data));

//    if (rc < 0) {
//        LOG_ERR("FAIL: write %s: %d", fname, rc);
//    }
    return sizeof(data);
}

uint32_t mcap_write_record_preamble(struct fs_file_t* fd, uint8_t type, uint64_t len) {
    ssize_t rc;
    rc = fs_write(fd, &type, sizeof(type));
    len = sys_cpu_to_le64(len);
    rc = fs_write(fd, &len, sizeof(len));

//    if (rc < 0) {
//        LOG_ERR("FAIL: write %s: %d", fname, rc);
//    }
    return sizeof(len) + sizeof(type);
}

uint32_t mcap_write_string(struct fs_file_t* fd, const char * data) {
    // mcap string format: 4 bytes length, followed by the UTF8 bytes
    ssize_t rc;
    uint32_t len = strlen(data);
    mcap_write_4bytes(fd, len);
    rc = fs_write(fd, &data, len);
    return sizeof(len) + len;
}

uint16_t mcap_add_schema(struct mcap_file_t* mcap_file, const char* name, const char* encoding,
        const uint8_t* schema_buffer, uint32_t schema_len) {
    // schema IDs cannot be 0, so the first schema will be 1
    uint16_t schema_id = ++mcap_file->statistics.schema_count;
    uint64_t len = sizeof(schema_id) + mcap_string_length(name) + mcap_string_length(encoding) + sizeof(schema_len) + schema_len;
    mcap_file->fd_offset += mcap_write_record_preamble(mcap_file->fd, MCAP_TYPE_SCHEMA, len);
    mcap_file->fd_offset += mcap_write_2bytes(mcap_file->fd, schema_id);
    mcap_file->fd_offset += mcap_write_string(mcap_file->fd, name);
    mcap_file->fd_offset += mcap_write_string(mcap_file->fd, encoding);

    mcap_file->fd_offset += mcap_write_4bytes(mcap_file->fd, schema_len);
    ssize_t rc;
    rc = fs_write(mcap_file->fd, &schema_buffer, schema_len);
    mcap_file->fd_offset += schema_len;

    return schema_id;
}

uint16_t mcap_add_channel(struct mcap_file_t* mcap_file, uint16_t schema_id, const char* topic,
        const char* encoding, const struct mcap_metadata_t* metadata) {
    uint16_t channel_id = mcap_file->statistics.channel_count++;
    uint64_t len = sizeof(channel_id) + sizeof(schema_id) + mcap_string_length(topic) + mcap_string_length(encoding) + sizeof(struct mcap_metadata_t);
    mcap_file->fd_offset += mcap_write_record_preamble(mcap_file->fd, MCAP_TYPE_CHANNEL, len);
    mcap_file->fd_offset += mcap_write_2bytes(mcap_file->fd, channel_id);
    mcap_file->fd_offset += mcap_write_2bytes(mcap_file->fd, schema_id);
    mcap_file->fd_offset += mcap_write_string(mcap_file->fd, topic);
    mcap_file->fd_offset += mcap_write_string(mcap_file->fd, encoding);

    //mcap_file->fd_offset += mcap_write_metadata(mcap_file->fd, metadata);
    mcap_file->fd_offset += mcap_write_4bytes(mcap_file->fd, 0);
    return channel_id;
}

uint16_t mcap_write_message(struct mcap_file_t* mcap_file, uint16_t channel_id, uint32_t sequence,
        uint64_t log_time, uint64_t publish_time, const uint8_t* data, uint32_t len) {
    uint64_t record_len = sizeof(channel_id) + sizeof(sequence) + sizeof(log_time) + sizeof(publish_time) + len;
    mcap_file->fd_offset += mcap_write_record_preamble(mcap_file->fd, MCAP_TYPE_MESSAGE, record_len);
    mcap_write_2bytes(mcap_file->fd, channel_id);
    mcap_write_4bytes(mcap_file->fd, sequence);
    mcap_write_8bytes(mcap_file->fd, log_time);
    mcap_write_8bytes(mcap_file->fd, publish_time);

    ssize_t rc;
    rc = fs_write(mcap_file->fd, &data, len);
    mcap_file->fd_offset += record_len;

    return record_len;
}

void mcap_write_header(struct mcap_file_t* mcap_file, const char* profile) {
    uint64_t len = mcap_string_length(profile) + mcap_string_length(MCAP_LIBRARY);
    mcap_file->fd_offset += mcap_write_record_preamble(mcap_file->fd, MCAP_TYPE_HEADER, len);
    mcap_file->fd_offset += mcap_write_string(mcap_file->fd, profile);
    mcap_file->fd_offset += mcap_write_string(mcap_file->fd, MCAP_LIBRARY);
}

void mcap_write_statistics(struct mcap_file_t* mcap_file, uint32_t* crc) {
    // TODO CRC32 calculation
    uint64_t len = sizeof(struct mcap_statistics_t) + sizeof (uint32_t); // TODO channel_message_counts
    mcap_file->fd_offset += mcap_write_record_preamble(mcap_file->fd, MCAP_TYPE_STATISTICS, len);

    mcap_write_8bytes(mcap_file->fd, mcap_file->statistics.message_count);
    mcap_write_2bytes(mcap_file->fd, mcap_file->statistics.schema_count);
    mcap_write_4bytes(mcap_file->fd, mcap_file->statistics.channel_count);
    mcap_write_4bytes(mcap_file->fd, mcap_file->statistics.attachment_count);
    mcap_write_4bytes(mcap_file->fd, mcap_file->statistics.metadata_count);
    mcap_write_4bytes(mcap_file->fd, mcap_file->statistics.chunk_count);
    mcap_write_8bytes(mcap_file->fd, mcap_file->statistics.message_start_time);
    mcap_write_8bytes(mcap_file->fd, mcap_file->statistics.message_end_time);
    mcap_write_4bytes(mcap_file->fd, 0);  // TODO channel_message_counts

    mcap_file->fd_offset += len;
}

struct mcap_footer_t mcap_write_summary(struct mcap_file_t* mcap_file) {
    struct mcap_footer_t footer;

    footer.summary_start = mcap_file->fd_offset;
    footer.summary_offset_start = 0;
    footer.summary_crc = 0;
    
    mcap_write_statistics(mcap_file, &footer.summary_crc);

    return footer;
}

void mcap_write_footer(struct mcap_file_t* mcap_file, struct mcap_footer_t* footer) {
    mcap_file->fd_offset += mcap_write_record_preamble(mcap_file->fd, MCAP_TYPE_FOOTER, sizeof(struct mcap_footer_t));

    mcap_write_8bytes(mcap_file->fd, footer->summary_start);
    mcap_write_8bytes(mcap_file->fd, footer->summary_offset_start);
    mcap_write_4bytes(mcap_file->fd, footer->summary_crc);
}

void mcap_finish(struct mcap_file_t* mcap_file) {
    struct mcap_footer_t footer = mcap_write_summary(mcap_file);
    mcap_write_footer(mcap_file, &footer);
    fs_write(mcap_file->fd, MCAP_MAGIC, sizeof(MCAP_MAGIC));
}
