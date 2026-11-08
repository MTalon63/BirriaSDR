/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Luigi C.
 */

/*
 * Original MT7961 firmware event framing and raw I/Q conversion
 *
 * This is the protocol emitted by firmware/iq_stream.S, not a general Wi-Fi
 * packet decoder. USB transfer boundaries can split or aggregate events; the
 * framer keeps at most one bounded incomplete event and consumes arbitrary
 * input fragments. Do not assume one libusb completion equals one DMA packet.
 *
 * An I/Q event is 8,240 bytes. Multi-byte wire fields are little-endian:
 *   Offset  Size  Meaning
 *        0     4  RXD0: class 7 in [31:27], length 8,236 in [15:0].
 *       24     4  MCU event word: 0x38000014 + payload size (8,192).
 *       28     1  Event ID 0xed.
 *       32     1  Extended event ID 0xf5.
 *       36     4  Packet sequence, starting at zero for this capture.
 *       40     4  Fresh boot nonce.
 *       44  8192  2,048 raw complex samples, Q16 followed by I16, or at 10
 *                 and 20 MSps 1,024 samples, two per 16-byte record followed
 *                 by two zero words.
 *     8236     4  USB trailer, outside both the RXD0 length and I/Q payload.
 * An opted-in recovering read also accepts a 48-byte gap event. Its length
 * words are 0x3800002c/0x38000014 and extended ID is 0xf6. Header offsets 8/12
 * contain source fault 8 or 9 and a monotonically increasing gap count. The
 * sequence is the NEXT data packet's sequence, not another payload. A marker
 * invalidates the preceding data packet, which the stream layer holds back.
 * The nonce and both counters remain continuous across an in-device recovery.
 * The remaining header fields are not interpreted here. The trailer may be a
 * neighboring SRAM word: ignore its contents and never deliver it as a sample.
 * One 40-byte ROM start ACK (event ID 1, status zero) is accepted; duplicate
 * ACKs are rejected. That event is left over from the boot handoff.
 *
 * Check event identity, nonce and sequence before delivering each payload.
 * Sequence comparison wraps at the 32-bit wire width while the host maintains
 * a 64-bit packet total. Reject gaps/repeats instead of scanning for a valid
 * next header: resynchronization would conceal a discontinuous capture.
 * bs_framer_finish() also rejects a partial event or a packet-total mismatch.
 * The stream layer separately checks firmware terminal state and DMA errors;
 * receiving a valid prefix alone does not establish a successful whole read.
 *
 * Each component is 14-bit two's complement in a 16-bit slot whose upper two
 * bits must be zero. Validate the entire payload before converting any samples.
 * Sign-extend bit 13 and swap Q,I to the API's native-endian int16_t I,Q order,
 * preserving the range -8192..8191. There is no normalization, DC correction,
 * DDC, averaging or decimation here. A new capture format must change this
 * decoder explicitly rather than silently reinterpreting the existing bytes.
 * tests/test_core.c exercises fragmentation, trailers and integrity failures.
 */
#include "internal.h"
#include <string.h>

/* Validate framing before releasing samples. Each event contains a monotonically
 * increasing sequence and fresh boot nonce; both detect gaps, repeats and stale
 * runs. The final USB trailer is outside the I/Q payload and may contain SRAM
 * data, so its value is deliberately not interpreted as another sample.
 */
static int consume_frame(struct bs_framer *framer, size_t length)
{
    const uint8_t *frame = framer->pending;
    if (length == 40) {
        if (frame[28] != 1 || frame[32] || framer->acknowledgements++)
            return BIRRIASDR_ERROR_PROTOCOL;
        return 0;
    }
    if (frame[28] != 0xed ||
        bs_get_le32(frame + 36) != (uint32_t)framer->packets ||
        bs_get_le32(frame + 40) != framer->nonce)
        return BIRRIASDR_ERROR_PROTOCOL;
    if (length == 48) {
        uint32_t state = bs_get_le32(frame + 8);
        if (!framer->gap || frame[32] != 0xf6 ||
            bs_get_le32(frame + 24) != 0x38000014u ||
            (state != 8 && state != 9) ||
            bs_get_le32(frame + 12) != (uint32_t)(framer->gaps + 1u))
            return BIRRIASDR_ERROR_PROTOCOL;
        BS_TRY(framer->gap(framer->context, state, framer->packets));
        ++framer->gaps;
        return 0;
    }
    if (frame[32] != 0xf5 ||
        bs_get_le32(frame + 24) != 0x38000014u + BS_PAYLOAD_BYTES)
        return BIRRIASDR_ERROR_PROTOCOL;
    BS_TRY(framer->payload(framer->context, frame + 44));
    ++framer->packets;
    return 0;
}

/* USB transfer boundaries are unrelated to DMA event boundaries. Assemble at
 * most one bounded frame, supporting every split point and aggregated events.
 * Invalid headers fail immediately instead of scanning ahead and hiding loss.
 */
int bs_framer_feed(struct bs_framer *framer, const uint8_t *data, size_t length)
{
    while (length) {
        size_t target = 4, copy;
        if (framer->used >= 4) {
            uint32_t word = bs_get_le32(framer->pending);
            uint32_t size = word & 0xffff;
            if (word >> 27 != 7 || (size != 36 && size != 44 && size != BS_FRAME_BYTES - 4))
                return BIRRIASDR_ERROR_PROTOCOL;
            target = size + 4;
        }
        copy = target - framer->used;
        if (copy > length)
            copy = length;
        memcpy(framer->pending + framer->used, data, copy);
        framer->used += copy;
        data += copy;
        length -= copy;
        if (framer->used == target && target != 4) {
            BS_TRY(consume_frame(framer, target));
            framer->used = 0;
        }
    }
    return 0;
}

/* A successful terminal mailbox is insufficient if USB ended mid-frame or lost
 * a whole packet. Match the independent firmware packet total as well.
 */
int bs_framer_finish(const struct bs_framer *framer, uint64_t expected)
{
    return framer->used || framer->packets != expected ? BIRRIASDR_ERROR_PROTOCOL : 0;
}

/* Raw SRAM is little-endian Q then I, 14-bit two's-complement in 16-bit slots.
 * Sign-extend and reorder to conventional native-endian I,Q without rescaling.
 * Validate the entire packet before making any part of it visible to a caller.
 */
#if (defined(__x86_64__) || defined(__i386__)) && defined(__GNUC__)
#include <immintrin.h>

/* 8 words per iteration. The scalar version pinned a core at 80 MSps, which is what
 * capped the Windows capture path; dispatching is runtime so non-AVX2 hosts still work. */
__attribute__((target("avx2")))
static int decode_iq_avx2(const uint8_t *raw, int16_t *iq, size_t samples)
{
    const __m256i bad_mask = _mm256_set1_epi32((int)0xc000c000u);
    const __m256i low14 = _mm256_set1_epi32(0x3fff);
    const __m256i bias = _mm256_set1_epi32(0x2000);
    size_t n = 0;

    for (; n + 8 <= samples; n += 8) {
        __m256i v = _mm256_loadu_si256((const __m256i *)(const void *)(raw + n * 4));
        __m256i bad = _mm256_and_si256(v, bad_mask);
        if (!_mm256_testz_si256(bad, bad))
            return BIRRIASDR_ERROR_PROTOCOL;
    }
    for (; n < samples; ++n)
        if (bs_get_le32(raw + n * 4) & 0xc000c000u)
            return BIRRIASDR_ERROR_PROTOCOL;

    for (n = 0; n + 8 <= samples; n += 8) {
        __m256i v = _mm256_loadu_si256((const __m256i *)(const void *)(raw + n * 4));
        __m256i iv = _mm256_sub_epi32(_mm256_xor_si256(
            _mm256_and_si256(_mm256_srli_epi32(v, 16), low14), bias), bias);
        __m256i qv = _mm256_sub_epi32(_mm256_xor_si256(
            _mm256_and_si256(v, low14), bias), bias);
        __m256i lo = _mm256_unpacklo_epi32(iv, qv);
        __m256i hi = _mm256_unpackhi_epi32(iv, qv);
        _mm256_storeu_si256((__m256i *)(void *)(iq + n * 2), _mm256_packs_epi32(lo, hi));
    }
    for (; n < samples; ++n) {
        uint32_t word = bs_get_le32(raw + n * 4);
        iq[n * 2] = (int16_t)((int32_t)(((word >> 16) & 0x3fff) ^ 0x2000) - 0x2000);
        iq[n * 2 + 1] = (int16_t)((int32_t)((word & 0x3fff) ^ 0x2000) - 0x2000);
    }
    return 0;
}

static int cpu_has_avx2(void)
{
    static int cached = -1;
    if (cached < 0) {
        __builtin_cpu_init();
        cached = __builtin_cpu_supports("avx2") ? 1 : 0;
    }
    return cached;
}
#endif

int bs_decode_iq(const uint8_t *raw, int16_t *iq, size_t samples)
{
#if (defined(__x86_64__) || defined(__i386__)) && defined(__GNUC__)
    if (cpu_has_avx2())
        return decode_iq_avx2(raw, iq, samples);
#endif
    for (size_t n = 0; n < samples; ++n)
        if (bs_get_le32(raw + n * 4) & 0xc000c000u)
            return BIRRIASDR_ERROR_PROTOCOL;
    for (size_t n = 0; n < samples; ++n) {
        uint32_t word = bs_get_le32(raw + n * 4);
        iq[n * 2] = (int16_t)((int32_t)(((word >> 16) & 0x3fff) ^ 0x2000) - 0x2000);
        iq[n * 2 + 1] = (int16_t)((int32_t)((word & 0x3fff) ^ 0x2000) - 0x2000);
    }
    return 0;
}

/* The packer used at 10 and 20 MSps (0x800210b8[17]) writes records of four
 * words: two consecutive output samples, then two zero words. Each output
 * sample is every fourth tap sample, so one record covers eight tap samples.
 * Keep the samples, require zero padding, and validate the whole packet before
 * writing any output.
 */
int bs_decode_iq_halved(const uint8_t *raw, int16_t *iq, size_t words)
{
    if (words % 4)
        return BIRRIASDR_ERROR_INVALID;
    for (size_t n = 0; n < words; n += 4)
        if (bs_get_le32(raw + n * 4 + 8) || bs_get_le32(raw + n * 4 + 12) ||
            ((bs_get_le32(raw + n * 4) | bs_get_le32(raw + n * 4 + 4)) & 0xc000c000u))
            return BIRRIASDR_ERROR_PROTOCOL;
    for (size_t n = 0; n < words; n += 4)
        BS_TRY(bs_decode_iq(raw + n * 4, iq + n, 2));
    return 0;
}
