// The greeting sound: four rising notes, generated as 16 bit mono PCM so the same sequence plays through an I2S amplifier on the
// board and can be written to a WAV file on the host.
#pragma once
#include "types.h"

namespace doormat {

struct Note {
  uint16_t freqHz;  // 0 is a rest
  uint16_t ms;
};

size_t greetingNoteCount();
const Note& greetingNote(size_t i);
uint32_t greetingTotalMs();

// Fills out[0..n) with the samples that start `startSample` samples into the greeting. Samples past the end are silence.
// amp is the peak amplitude (0..32767). Each note has a 10 ms linear fade in and out so there is no click between notes.
void renderGreetingPcm(int16_t* out, size_t n, uint32_t startSample, uint32_t sampleRate, int16_t amp);

}  // namespace doormat
