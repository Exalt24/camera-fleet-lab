#include "ble.h"

#include <NimBLEDevice.h>

static const char* kService = "6d6f6174-0000-4d41-5400-646f6f726d61";
static const char* kCommand = "6d6f6174-0001-4d41-5400-646f6f726d61";
static const char* kStatus = "6d6f6174-0002-4d41-5400-646f6f726d61";

static NimBLECharacteristic* statusChar = nullptr;
static portMUX_TYPE mux = portMUX_INITIALIZER_UNLOCKED;
static char pending[257];
static volatile size_t pendingLen = 0;

class CommandCallbacks : public NimBLECharacteristicCallbacks {
  void onWrite(NimBLECharacteristic* c) override {
    const std::string v = c->getValue();
    if (v.empty() || v.size() > 256) return;  // an oversize write is dropped, the parser would refuse it anyway
    portENTER_CRITICAL(&mux);
    memcpy(pending, v.data(), v.size());
    pendingLen = v.size();
    portEXIT_CRITICAL(&mux);
  }
};

void bleBegin(const char* deviceId) {
  char name[32];
  snprintf(name, sizeof(name), "doormat-%s", deviceId);
  NimBLEDevice::init(name);
  NimBLEServer* server = NimBLEDevice::createServer();
  NimBLEService* svc = server->createService(kService);
  NimBLECharacteristic* cmd = svc->createCharacteristic(kCommand, NIMBLE_PROPERTY::WRITE);
  cmd->setCallbacks(new CommandCallbacks());
  statusChar = svc->createCharacteristic(kStatus, NIMBLE_PROPERTY::READ | NIMBLE_PROPERTY::NOTIFY);
  svc->start();
  NimBLEAdvertising* adv = NimBLEDevice::getAdvertising();
  adv->addServiceUUID(kService);
  adv->start();
}

size_t bleTake(char* out, size_t cap) {
  size_t n = 0;
  portENTER_CRITICAL(&mux);
  if (pendingLen > 0 && pendingLen < cap) {
    n = pendingLen;
    memcpy(out, pending, n);
    pendingLen = 0;
  }
  portEXIT_CRITICAL(&mux);
  return n;
}

void bleSetStatus(const char* json) {
  if (!statusChar) return;
  statusChar->setValue(json);
  statusChar->notify();
}
