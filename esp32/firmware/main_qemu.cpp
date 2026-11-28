// The device logic with scripted peripherals, for Espressif's QEMU. QEMU does not emulate the ADC, I2S, RMT (LED strip) or Wi-Fi,
// so this build replaces the pins with the scripted evening in lib/doormat_core/scenario.cpp and prints what the device does to
// the serial port. The point is the CPU: the same C++ runs on the Xtensa core under QEMU, and its trace is compared line by line with
// the one the host program prints (qemu/compare_trace.py).
#include <Arduino.h>

#include "scenario.h"

static void emit(const char* line, void*) { Serial.println(line); }

void setup() {
  Serial.begin(115200);
  delay(200);
  Serial.println("QEMU-RUN-BEGIN");
  doormat::runScenario(emit, nullptr);
  Serial.println("QEMU-RUN-END");
}

void loop() { delay(1000); }
