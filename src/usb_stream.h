/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Luigi C.
 */
#ifndef BIRRIASDR_USB_STREAM_H
#define BIRRIASDR_USB_STREAM_H
#include "internal.h"
/* One bulk-IN URB. 64 KiB meant ~5000 completions/s at 80 MSps, and that per-transfer
 * overhead through libusbK on Windows cost ~13% of the required 320 MB/s. */
#ifndef BS_USB_BYTES
#define BS_USB_BYTES 65536u
#endif
struct bs_reader;
int bs_reader_create(birriasdr_dev_t *dev, unsigned depth, struct bs_reader **out);
int bs_reader_start(struct bs_reader *reader);
int bs_reader_take(struct bs_reader *reader, uint8_t *data, size_t *length, unsigned timeout_ms);
void bs_reader_destroy(struct bs_reader *reader);
#endif
