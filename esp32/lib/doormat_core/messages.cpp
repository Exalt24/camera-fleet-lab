#include "messages.h"

#include <string.h>

namespace doormat {

size_t sanitizeText(const char* in, char* out, size_t cap) {
  if (!out || cap == 0) return 0;
  out[0] = '\0';
  if (!in) return 0;
  size_t n = 0;
  bool lastSpace = true;  // swallows leading spaces
  for (const char* p = in; *p && n + 1 < cap; p++) {
    const unsigned char c = static_cast<unsigned char>(*p);
    if (c < 0x20 || c > 0x7E) continue;  // control characters and anything outside ASCII are dropped
    if (c == ' ') {
      if (lastSpace) continue;
      lastSpace = true;
    } else {
      lastSpace = false;
    }
    out[n++] = static_cast<char>(c);
  }
  while (n > 0 && out[n - 1] == ' ') n--;
  out[n] = '\0';
  return n;
}

MessageScheduler::MessageScheduler()
    : count_(0), next_(0), hasShown_(false), shownAt_(0), holdUntil_(0), lastChange_(0) {
  shown_[0] = '\0';
  static const char* const kDefaults[] = {"Welcome home!", "Hello, friend!", "Great to see you", "Have a lovely day", "Wipe your feet :)"};
  for (size_t i = 0; i < sizeof(kDefaults) / sizeof(kDefaults[0]); i++) add(kDefaults[i]);
}

bool MessageScheduler::add(const char* text) {
  if (count_ >= kMaxMessages) return false;
  char clean[kMaxLen + 1];
  if (sanitizeText(text, clean, sizeof(clean)) == 0) return false;
  memcpy(list_[count_], clean, sizeof(clean));
  count_++;
  return true;
}

void MessageScheduler::show(const char* text, uint32_t nowMs) {
  strncpy(shown_, text, kMaxLen);
  shown_[kMaxLen] = '\0';
  hasShown_ = true;
  shownAt_ = nowMs;
  lastChange_ = nowMs;
  holdUntil_ = nowMs + kHoldMs;
}

void MessageScheduler::onGreeting(uint32_t nowMs) {
  if (count_ == 0) return;
  show(list_[next_], nowMs);
  next_ = (next_ + 1) % count_;
}

bool MessageScheduler::select(size_t index, uint32_t nowMs) {
  if (index >= count_) return false;
  show(list_[index], nowMs);
  next_ = (index + 1) % count_;
  return true;
}

bool MessageScheduler::showCustom(const char* text, uint32_t nowMs) {
  char clean[kMaxLen + 1];
  if (sanitizeText(text, clean, sizeof(clean)) == 0) return false;
  show(clean, nowMs);
  return true;
}

void MessageScheduler::tick(uint32_t nowMs, bool occupied) {
  if (!occupied || !hasShown_ || count_ == 0) return;
  if (static_cast<uint32_t>(nowMs - lastChange_) >= kRotateMs) {
    show(list_[next_], nowMs);
    next_ = (next_ + 1) % count_;
  }
}

const char* MessageScheduler::current(uint32_t nowMs) const {
  if (!hasShown_) return "";
  return static_cast<uint32_t>(nowMs - shownAt_) < kHoldMs ? shown_ : "";
}

}  // namespace doormat
