// The device logic (lib/doormat_core) as a line driven program for the host. The emulation server and the tests write one command per
// line to stdin and read one answer per line from stdout. It is the same code the ESP32 firmware links, not a second implementation.
//
//   tick <ms> <pressure> <mic>      one step of the device           -> {"ev":..,"greet":..,"sound":..}
//   cmd <ms> <route|-> <json body>  a REST, WebSocket or MQTT command -> {"ok":true,"type":".."} or {"ok":false,"err":".."}
//   status <ms> <id> <net>          the status JSON
//   frame <ms> <samples>            a sampled LED frame event
//   eyes <ms>                       the display as a hex encoded 1 bit BMP
//   messages                        the message list
//   wav <path> <rate>               the greeting sound as a mono 16 bit WAV file
//   scenario                        the scripted evening, then a line "END"
//   quit
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "app.h"
#include "scenario.h"
#include "tones.h"

using namespace doormat;

static const size_t kLeds = 48;

static const char* evName(PresenceEvent e) {
  switch (e) {
    case PresenceEvent::StepOn: return "step_on";
    case PresenceEvent::StepOff: return "step_off";
    case PresenceEvent::None: break;
  }
  return "none";
}

static const char* typeName(CmdType t) {
  switch (t) {
    case CmdType::Greet: return "greet";
    case CmdType::Led: return "led";
    case CmdType::Message: return "message";
    case CmdType::Status: return "status";
    case CmdType::Wifi: return "wifi";
    case CmdType::None: break;
  }
  return "none";
}

static void emitLine(const char* line, void*) {
  puts(line);
}

static void writeWav(const char* path, uint32_t rate) {
  const size_t n = static_cast<size_t>(rate) * greetingTotalMs() / 1000;
  int16_t* pcm = static_cast<int16_t*>(malloc(n * sizeof(int16_t)));
  if (!pcm) {
    puts("{\"ok\":false,\"err\":\"memory\"}");
    return;
  }
  renderGreetingPcm(pcm, n, 0, rate, 12000);
  FILE* f = fopen(path, "wb");
  if (!f) {
    free(pcm);
    puts("{\"ok\":false,\"err\":\"open\"}");
    return;
  }
  const uint32_t dataBytes = static_cast<uint32_t>(n * 2);
  uint8_t h[44] = {'R', 'I', 'F', 'F', 0, 0, 0, 0, 'W', 'A', 'V', 'E', 'f', 'm', 't', ' ', 16, 0, 0, 0, 1, 0, 1, 0};
  auto put32 = [&h](size_t at, uint32_t v) {
    for (int i = 0; i < 4; i++) h[at + i] = static_cast<uint8_t>(v >> (8 * i));
  };
  put32(4, 36 + dataBytes);
  put32(24, rate);
  put32(28, rate * 2);
  h[32] = 2;
  h[34] = 16;
  memcpy(h + 36, "data", 4);
  put32(40, dataBytes);
  fwrite(h, 1, sizeof(h), f);
  fwrite(pcm, 2, n, f);
  fclose(f);
  free(pcm);
  printf("{\"ok\":true,\"samples\":%lu}\n", static_cast<unsigned long>(n));
}

int main() {
  DoormatApp app;
  char line[1024];
  while (fgets(line, sizeof(line), stdin)) {
    size_t len = strlen(line);
    while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) line[--len] = '\0';
    if (strncmp(line, "tick ", 5) == 0) {
      unsigned long ms;
      int pressure, mic;
      if (sscanf(line + 5, "%lu %d %d", &ms, &pressure, &mic) != 3 || pressure < 0 || pressure > 65535 || mic < 0 || mic > 100) {
        puts("{\"ok\":false,\"err\":\"bad_tick\"}");
      } else {
        const StepResult r = app.step(static_cast<uint32_t>(ms), static_cast<uint16_t>(pressure), static_cast<uint8_t>(mic));
        printf("{\"ev\":\"%s\",\"greet\":%s,\"sound\":%s}\n", evName(r.event), r.greeted ? "true" : "false",
               app.takeGreeting() ? "true" : "false");
      }
    } else if (strncmp(line, "cmd ", 4) == 0) {
      // cmd <ms> <route|-> <body>
      unsigned long ms;
      char route[16];
      int consumed = 0;
      if (sscanf(line + 4, "%lu %15s %n", &ms, route, &consumed) < 2) {
        puts("{\"ok\":false,\"err\":\"bad_cmd_line\"}");
        continue;
      }
      const char* body = line + 4 + consumed;
      Command c;
      const ParseError pe = parseCommand(strcmp(route, "-") == 0 ? nullptr : route, body, strlen(body), &c);
      if (pe != ParseError::Ok) {
        printf("{\"ok\":false,\"err\":\"%s\"}\n", errorName(pe));
      } else {
        const ApplyResult ar = app.apply(c, static_cast<uint32_t>(ms));
        if (ar == ApplyResult::BadIndex) {
          puts("{\"ok\":false,\"err\":\"bad_index\"}");
        } else if (c.type == CmdType::Wifi) {
          // the credentials never go back out, only the fact that they were accepted
          puts("{\"ok\":true,\"type\":\"wifi\"}");
        } else {
          printf("{\"ok\":true,\"type\":\"%s\"}\n", typeName(c.type));
        }
      }
    } else if (strncmp(line, "status ", 7) == 0) {
      unsigned long ms;
      char id[32], net[8];
      char out[512];
      if (sscanf(line + 7, "%lu %31s %7s", &ms, id, net) != 3 ||
          formatStatus(out, sizeof(out), app.status(static_cast<uint32_t>(ms), id, net)) == 0) {
        puts("{\"ok\":false,\"err\":\"bad_status\"}");
      } else {
        puts(out);
      }
    } else if (strncmp(line, "frame ", 6) == 0) {
      unsigned long ms, samples;
      char out[512];
      Rgb leds[kLeds];
      if (sscanf(line + 6, "%lu %lu", &ms, &samples) != 2) {
        puts("{\"ok\":false,\"err\":\"bad_frame\"}");
      } else {
        app.renderLeds(static_cast<uint32_t>(ms), leds, kLeds);
        if (formatFrameEvent(out, sizeof(out), leds, kLeds, samples) == 0) puts("{\"ok\":false,\"err\":\"bad_frame\"}");
        else puts(out);
      }
    } else if (strncmp(line, "eyes ", 5) == 0) {
      unsigned long ms = strtoul(line + 5, nullptr, 10);
      uint8_t fb[kEyeBytes];
      uint8_t bmp[1200];
      renderEyes(app.eyes(static_cast<uint32_t>(ms)), fb);
      const size_t n = framebufferToBmp1bpp(fb, kEyeW, kEyeH, bmp, sizeof(bmp));
      for (size_t i = 0; i < n; i++) printf("%02x", bmp[i]);
      putchar('\n');
    } else if (strcmp(line, "messages") == 0) {
      printf("{\"messages\":[");
      for (size_t i = 0; i < app.messages().count(); i++) {
        char esc[80];
        jsonEscape(app.messages().at(i), esc, sizeof(esc));
        printf("%s\"%s\"", i ? "," : "", esc);
      }
      puts("]}");
    } else if (strncmp(line, "wav ", 4) == 0) {
      char path[512];
      unsigned long rate = 16000;
      if (sscanf(line + 4, "%511s %lu", path, &rate) < 1) puts("{\"ok\":false,\"err\":\"bad_wav\"}");
      else writeWav(path, static_cast<uint32_t>(rate));
    } else if (strcmp(line, "scenario") == 0) {
      runScenario(emitLine, nullptr);
      puts("END");
    } else if (strcmp(line, "quit") == 0) {
      break;
    } else {
      puts("{\"ok\":false,\"err\":\"unknown_line\"}");
    }
    fflush(stdout);
  }
  return 0;
}
