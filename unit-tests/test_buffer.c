#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#include <cmocka.h>

#include "common/buffer.h"

static void test_buffer_can_read(void **state) {
    (void) state;

    uint8_t temp[20] = {0};
    buffer_t buf = {.ptr = temp, .size = sizeof(temp), .offset = 0};

    assert_true(buffer_can_read(&buf, 20));

    assert_true(buffer_seek_cur(&buf, 20));
    assert_false(buffer_can_read(&buf, 1));
}

static void test_buffer_seek(void **state) {
    (void) state;

    uint8_t temp[20] = {0};
    buffer_t buf = {.ptr = temp, .size = sizeof(temp), .offset = 0};

    assert_true(buffer_can_read(&buf, 20));

    assert_true(buffer_seek_cur(&buf, 20));  // seek at offset 20
    assert_false(buffer_can_read(&buf, 1));  // can't read 1 byte
    assert_false(buffer_seek_cur(&buf, 1));  // can't move at offset 21

    assert_true(buffer_seek_end(&buf, 19));
    assert_int_equal(buf.offset, 1);
    assert_false(buffer_seek_end(&buf, 21));  // can't seek at offset -1

    assert_true(buffer_seek_set(&buf, 10));
    assert_int_equal(buf.offset, 10);
    assert_false(buffer_seek_set(&buf, 21));  // can't seek at offset 21
}

static void test_buffer_read(void **state) {
    (void) state;

    // clang-format off
    uint8_t temp[15] = {
        0xFF,
        0x01, 0x02,
        0x03, 0x04, 0x05, 0x06,
        0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E
    };
    buffer_t buf = {.ptr = temp, .size = sizeof(temp), .offset = 0};

    uint8_t first = 0;
    assert_true(buffer_read_u8(&buf, &first));
    assert_int_equal(first, 255);                // 0xFF
    assert_true(buffer_seek_end(&buf, 0));       // seek at offset 19
    assert_false(buffer_read_u8(&buf, &first));  // can't read 1 byte

    uint16_t second = 0;
    assert_true(buffer_seek_set(&buf, 1));             // set back to offset 1
    assert_true(buffer_read_u16(&buf, &second, BE));   // big endian
    assert_int_equal(second, 258);                     // 0x01 0x02
    assert_true(buffer_seek_set(&buf, 1));             // set back to offset 1
    assert_true(buffer_read_u16(&buf, &second, LE));   // little endian
    assert_int_equal(second, 513);                     // 0x02 0x01
    assert_true(buffer_seek_set(&buf, 14));            // seek at offset 14
    assert_false(buffer_read_u16(&buf, &second, BE));  // can't read 2 bytes

    uint32_t third = 0;
    assert_true(buffer_seek_set(&buf, 3));            // set back to offset 3
    assert_true(buffer_read_u32(&buf, &third, BE));   // big endian
    assert_int_equal(third, 50595078);                // 0x03 0x04 0x05 0x06
    assert_true(buffer_seek_set(&buf, 3));            // set back to offset 3
    assert_true(buffer_read_u32(&buf, &third, LE));   // little endian
    assert_int_equal(third, 100992003);               // 0x06 0x05 0x04 0x03
    assert_true(buffer_seek_set(&buf, 12));           // seek at offset 12
    assert_false(buffer_read_u32(&buf, &third, BE));  // can't read 4 bytes

    uint64_t fourth = 0;
    assert_true(buffer_seek_set(&buf, 7));             // set back to offset 7
    assert_true(buffer_read_u64(&buf, &fourth, BE));   // big endian
    assert_int_equal(fourth, 506664896818842894);      // 0x07 0x08 0x09 0x0A 0x0B 0x0C 0x0D 0x0E
    assert_true(buffer_seek_set(&buf, 7));             // set back to offset 7
    assert_true(buffer_read_u64(&buf, &fourth, LE));   // little endian
    assert_int_equal(fourth, 1012478732780767239);     // 0x0E 0x0D 0x0C 0x0B 0x0A 0x09 0x08 0x07
    assert_true(buffer_seek_set(&buf, 8));             // seek at offset 8
    assert_false(buffer_read_u64(&buf, &fourth, BE));  // can't read 8 bytes


    uint8_t bytes[32];

    memset(bytes, 0x42, sizeof(bytes));                // we use 0x42 as marker for data that is left unchanged

    assert_true(buffer_seek_set(&buf, 7));             // set back to offset 7
    assert_true(buffer_read_bytes(&buf, bytes, 0));   // read zero bytes
    assert_int_equal(bytes[0], 0x42);

    memset(bytes, 0x42, sizeof(bytes));
    assert_true(buffer_seek_set(&buf, 7));             // set back to offset 7
    assert_true(buffer_read_bytes(&buf, bytes, 1));
    assert_int_equal(bytes[0], 0x07);
    assert_int_equal(bytes[1], 0x42);

    memset(bytes, 0x42, sizeof(bytes));
    assert_true(buffer_seek_set(&buf, 7));             // set back to offset 7
    assert_true(buffer_read_bytes(&buf, bytes, 5));
    assert_int_equal(bytes[0], 0x07);
    assert_int_equal(bytes[1], 0x08);
    assert_int_equal(bytes[2], 0x09);
    assert_int_equal(bytes[3], 0x0A);
    assert_int_equal(bytes[4], 0x0B);
    assert_int_equal(bytes[5], 0x42);


    // clang-format off
    uint8_t temp_varint[] = {
        0xFC, // 1 byte varint
        0xFD, 0x00, 0x01, // 2 bytes varint
        0xFE, 0x00, 0x01, 0x02, 0x03,  // 4 bytes varint
        0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 // 8 bytes varint

    };
    buffer_t buf_varint = {.ptr = temp_varint, .size = sizeof(temp_varint), .offset = 0};
    uint64_t varint = 0;
    assert_true(buffer_read_varint(&buf_varint, &varint));
    assert_int_equal(varint, 0xFC);
    assert_true(buffer_read_varint(&buf_varint, &varint));
    assert_int_equal(varint, 0x0100);
    assert_true(buffer_read_varint(&buf_varint, &varint));
    assert_int_equal(varint, 0x03020100);
    assert_true(buffer_read_varint(&buf_varint, &varint));
    assert_int_equal(varint, 0x0706050403020100);
    assert_false(buffer_read_varint(&buf_varint, &varint));
}

static void test_buffer_write(void **state) {
    (void) state;

    uint8_t template[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };

    uint8_t data[sizeof(template)];

    memcpy(data, template, sizeof(template));
    buffer_t buf = {.ptr = data, .size = sizeof(data), .offset = 0};

    // TEST buffer_write_u8
    assert_true(buffer_write_u8(&buf, 42));
    assert_int_equal(data[0], 42);
    assert_int_equal(data[1], 0x01);
    assert_int_equal(buf.offset, 1);
    buffer_seek_end(&buf, 0);
    assert_false(buffer_write_u8(&buf, 42));
    assert_int_equal(buf.offset, buf.size);
    buffer_seek_end(&buf, 1);
    assert_true(buffer_write_u8(&buf, 42));

    // reset data
    memcpy(data, template, sizeof(template));
    buffer_seek_set(&buf, 0);


    // TEST buffer_write_u16
    buffer_seek_set(&buf, 3);
    assert_true(buffer_write_u16(&buf, 0x3344, BE));
    assert_int_equal(data[2], 0x02);
    assert_int_equal(data[3], 0x33);
    assert_int_equal(data[4], 0x44);
    assert_int_equal(data[5], 0x05);
    assert_int_equal(buf.offset, 5);
    buffer_seek_set(&buf, 3);
    assert_true(buffer_write_u16(&buf, 0x3344, LE));
    assert_int_equal(data[2], 0x02);
    assert_int_equal(data[3], 0x44);
    assert_int_equal(data[4], 0x33);
    assert_int_equal(data[5], 0x05);
    assert_int_equal(buf.offset, 5);

    buffer_seek_end(&buf, 1);
    assert_false(buffer_write_u16(&buf, 0x4242, BE));                     // not enough space
    assert_int_equal(data[sizeof(data) - 1], template[sizeof(data) - 1]); // shouldn't change data if not enough space
    buffer_seek_end(&buf, 2);
    assert_true(buffer_write_u16(&buf, 0x4242, BE));                      // enough space this time 

    // reset data
    memcpy(data, template, sizeof(template));
    buffer_seek_set(&buf, 0);


    // TEST buffer_write_u32
    buffer_seek_set(&buf, 3);
    assert_true(buffer_write_u32(&buf, 0x33445566, BE));
    assert_int_equal(data[2], 0x02);
    assert_int_equal(data[3], 0x33);
    assert_int_equal(data[4], 0x44);
    assert_int_equal(data[5], 0x55);
    assert_int_equal(data[6], 0x66);
    assert_int_equal(data[7], 0x07);
    assert_int_equal(buf.offset, 7);
    buffer_seek_set(&buf, 3);
    assert_true(buffer_write_u32(&buf, 0x33445566, LE));
    assert_int_equal(data[2], 0x02);
    assert_int_equal(data[3], 0x66);
    assert_int_equal(data[4], 0x55);
    assert_int_equal(data[5], 0x44);
    assert_int_equal(data[6], 0x33);
    assert_int_equal(data[7], 0x07);
    assert_int_equal(buf.offset, 7);

    buffer_seek_end(&buf, 3);
    assert_false(buffer_write_u32(&buf, 0x42424242, BE));                 // not enough space
    assert_int_equal(data[sizeof(data) - 1], template[sizeof(data) - 1]); // shouldn't change data if not enough space
    buffer_seek_end(&buf, 4);
    assert_true(buffer_write_u32(&buf, 0x42424242, BE));                  // enough space this time 

    // reset data
    memcpy(data, template, sizeof(template));
    buffer_seek_set(&buf, 0);


    // TEST buffer_write_u64
    buffer_seek_set(&buf, 3);
    assert_true(buffer_write_u64(&buf, 0x33445566778899aaULL, BE));
    assert_int_equal(data[2], 0x02);
    assert_int_equal(data[3], 0x33);
    assert_int_equal(data[4], 0x44);
    assert_int_equal(data[5], 0x55);
    assert_int_equal(data[6], 0x66);
    assert_int_equal(data[7], 0x77);
    assert_int_equal(data[8], 0x88);
    assert_int_equal(data[9], 0x99);
    assert_int_equal(data[10], 0xaa);
    assert_int_equal(data[11], 0x0b);
    assert_int_equal(buf.offset, 11);
    buffer_seek_set(&buf, 3);
    assert_true(buffer_write_u64(&buf, 0x33445566778899aaULL, LE));
    assert_int_equal(data[2], 0x02);
    assert_int_equal(data[3], 0xaa);
    assert_int_equal(data[4], 0x99);
    assert_int_equal(data[5], 0x88);
    assert_int_equal(data[6], 0x77);
    assert_int_equal(data[7], 0x66);
    assert_int_equal(data[8], 0x55);
    assert_int_equal(data[9], 0x44);
    assert_int_equal(data[10], 0x33);
    assert_int_equal(data[11], 0x0b);
    assert_int_equal(buf.offset, 11);

    buffer_seek_end(&buf, 7);
    assert_false(buffer_write_u64(&buf, 0x4242424242424242ULL, BE));         // not enough space
    assert_int_equal(data[sizeof(data) - 1], template[sizeof(data) - 1]); // shouldn't change data if not enough space
    buffer_seek_end(&buf, 8);
    assert_true(buffer_write_u64(&buf, 0x4242424242424242ULL, BE));          // enough space this time 

}

static void test_buffer_create(void **state) {
    (void) state;

    uint8_t data[32];

    buffer_t buffer = buffer_create(data, 15);

    assert_ptr_equal(buffer.ptr, data);
    assert_int_equal(buffer.size, 15);
    assert_int_equal(buffer.offset, 0);
}


int main() {
    const struct CMUnitTest tests[] = {cmocka_unit_test(test_buffer_can_read),
                                       cmocka_unit_test(test_buffer_seek),
                                       cmocka_unit_test(test_buffer_read),
                                       cmocka_unit_test(test_buffer_write),
                                       cmocka_unit_test(test_buffer_create)};

    return cmocka_run_group_tests(tests, NULL, NULL);
}
