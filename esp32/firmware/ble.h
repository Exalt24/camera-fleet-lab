// BLE: one command characteristic (write the same JSON the REST API takes) and one status characteristic (read and notify).
// No pairing or encryption is set up, so anyone in radio range can write to it. See the limits in esp32/README.md.
#pragma once
#include <Arduino.h>

void bleBegin(const char* deviceId);
// Copies a command written since the last call into out and returns its length, or 0 when there is none.
size_t bleTake(char* out, size_t cap);
void bleSetStatus(const char* json);
