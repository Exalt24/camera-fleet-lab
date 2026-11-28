// The short messages the display shows after a greeting, and when each one is shown.
#pragma once
#include "types.h"

namespace doormat {

// Printable ASCII only, trimmed, cut to cap-1 characters. Returns the length written, 0 when nothing printable is left.
size_t sanitizeText(const char* in, char* out, size_t cap);

class MessageScheduler {
 public:
  static const size_t kMaxMessages = 8;
  static const size_t kMaxLen = 32;               // characters, one line on a 128 pixel OLED at size 1 is 21, size 2 is 10
  static const uint32_t kHoldMs = 6000;           // a shown message stays this long after the last thing that set it
  static const uint32_t kRotateMs = 4000;         // while someone stands on the mat the next message follows after this

  MessageScheduler();
  size_t count() const { return count_; }
  const char* at(size_t i) const { return i < count_ ? list_[i] : ""; }
  bool add(const char* text);                     // false when the list is full or the text has nothing printable
  void onGreeting(uint32_t nowMs);                // shows the next message in turn
  bool select(size_t index, uint32_t nowMs);      // false for an index that does not exist
  bool showCustom(const char* text, uint32_t nowMs);
  void tick(uint32_t nowMs, bool occupied);       // rotation while the mat is occupied
  // The text to show, or an empty string when the display should show only the eyes.
  const char* current(uint32_t nowMs) const;

 private:
  void show(const char* text, uint32_t nowMs);
  char list_[kMaxMessages][kMaxLen + 1];
  size_t count_;
  size_t next_;
  char shown_[kMaxLen + 1];
  bool hasShown_;
  uint32_t shownAt_;
  uint32_t holdUntil_;
  uint32_t lastChange_;
};

}  // namespace doormat
