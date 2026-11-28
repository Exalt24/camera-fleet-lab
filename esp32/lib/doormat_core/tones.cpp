#include "tones.h"

#include <math.h>

namespace doormat {

namespace {
const Note kGreeting[] = {{523, 130}, {659, 130}, {784, 130}, {1047, 260}};  // C5 E5 G5 C6
const size_t kCount = sizeof(kGreeting) / sizeof(kGreeting[0]);
const uint32_t kFadeMs = 10;
}  // namespace

size_t greetingNoteCount() { return kCount; }
const Note& greetingNote(size_t i) { return kGreeting[i < kCount ? i : kCount - 1]; }

uint32_t greetingTotalMs() {
  uint32_t t = 0;
  for (size_t i = 0; i < kCount; i++) t += kGreeting[i].ms;
  return t;
}

void renderGreetingPcm(int16_t* out, size_t n, uint32_t startSample, uint32_t sampleRate, int16_t amp) {
  if (!out || n == 0) return;
  if (amp < 0) amp = 0;
  for (size_t k = 0; k < n; k++) {
    const uint64_t sample = static_cast<uint64_t>(startSample) + k;
    const uint64_t tUs = sample * 1000000ull / sampleRate;
    uint64_t noteStartUs = 0;
    int16_t value = 0;
    for (size_t i = 0; i < kCount; i++) {
      const uint64_t noteUs = static_cast<uint64_t>(kGreeting[i].ms) * 1000ull;
      if (tUs < noteStartUs + noteUs) {
        if (kGreeting[i].freqHz != 0) {
          const double within = static_cast<double>(tUs - noteStartUs) / 1e6;
          const double leftMs = static_cast<double>(noteStartUs + noteUs - tUs) / 1000.0;
          const double inMs = within * 1000.0;
          double env = 1.0;
          if (inMs < kFadeMs) env = inMs / kFadeMs;
          if (leftMs < kFadeMs && leftMs / kFadeMs < env) env = leftMs / kFadeMs;
          value = static_cast<int16_t>(sin(6.283185307179586 * kGreeting[i].freqHz * within) * amp * env);
        }
        break;
      }
      noteStartUs += noteUs;
    }
    out[k] = value;
  }
}

}  // namespace doormat
