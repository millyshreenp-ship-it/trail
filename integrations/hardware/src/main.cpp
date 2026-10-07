#include <Arduino.h>
#include <ArduinoJson.h>
#include <Adafruit_SSD1306.h>
#include <Ed25519.h>
#include <NimBLEDevice.h>
#include <Preferences.h>
#include <Wire.h>
#include <esp_random.h>
#include <mbedtls/base64.h>

#ifndef TRAIL_SERVER_KEY_B64
#define TRAIL_SERVER_KEY_B64 ""
#endif

constexpr int BUTTON_PIN = 3;
constexpr size_t MAX_PACKET = 2048;
const char* SERVICE_UUID = "126d11b0-ef1e-4d35-a7cb-560a407c01a1";
const char* RECEIVE_UUID = "126d11b1-ef1e-4d35-a7cb-560a407c01a1";
const char* RESPONSE_UUID = "126d11b2-ef1e-4d35-a7cb-560a407c01a1";
const char* IDENTITY_UUID = "126d11b3-ef1e-4d35-a7cb-560a407c01a1";
Adafruit_SSD1306 display(128, 64, &Wire, -1);
uint8_t privateKey[32];
uint8_t publicKey[32];
uint8_t serverKey[32];
String deviceId;
String signedMessage;
String challengeId;
String serialInput;
String bleInput;
bool pending = false;
bool released = false;
bool pinned = false;
unsigned long receivedAt = 0;
unsigned long holdStarted = 0;
NimBLECharacteristic* responses = nullptr;
QueueHandle_t incoming;

struct BleChunk {
    uint16_t length;
    char bytes[241];
};

String encodeBase64(const uint8_t* bytes, size_t length) {
    char buffer[128];
    size_t written = 0;
    if (mbedtls_base64_encode(reinterpret_cast<unsigned char*>(buffer), sizeof(buffer), &written, bytes, length) != 0) return "";
    return String(buffer).substring(0, written);
}

bool decodeBase64(const char* text, uint8_t* output, size_t capacity, size_t expected) {
    size_t written = 0;
    return mbedtls_base64_decode(output, capacity, &written, reinterpret_cast<const unsigned char*>(text), strlen(text)) == 0 && written == expected;
}

void show(const String& first, const String& second = "", const String& third = "", const String& fourth = "") {
    display.clearDisplay();
    display.setTextColor(SSD1306_WHITE);
    display.setTextSize(1);
    display.setCursor(0, 0);
    display.println(first);
    display.println(second);
    display.println(third);
    display.println(fourth);
    display.display();
}

void acceptPacket(const String& packet) {
    pending = false;
    if (!pinned || packet.length() > MAX_PACKET) { show("Challenge rejected", "Pinned key required"); return; }
    JsonDocument envelope;
    if (deserializeJson(envelope, packet)) { show("Invalid packet"); return; }
    const char* messageText = envelope["message_b64"] | "";
    uint8_t message[1024];
    uint8_t signature[64];
    size_t length = 0;
    if (mbedtls_base64_decode(message, sizeof(message) - 1, &length, reinterpret_cast<const unsigned char*>(messageText), strlen(messageText)) != 0 || !decodeBase64(envelope["server_signature_b64"] | "", signature, sizeof(signature), 64) || !Ed25519::verify(signature, serverKey, message, length)) { show("Signature rejected"); return; }
    message[length] = 0;
    JsonDocument payload;
    if (deserializeJson(payload, message, length) || String(payload["schema_version"] | "") != "earlytrace.device.challenge.v1" || String(payload["device_id"] | "") != deviceId || String(payload["action"] | "") != "ACKNOWLEDGE_REVIEW") { show("Binding rejected"); return; }
    signedMessage = String(reinterpret_cast<char*>(message));
    challengeId = String(payload["challenge_id"] | "");
    if (challengeId.length() < 20 || challengeId.length() > 80) { show("Challenge rejected"); return; }
    pending = true;
    released = false;
    holdStarted = 0;
    receivedAt = millis();
    show("EARLYTRACE / VERIFY", String(payload["amount_bucket"] | "bucketed"), String(payload["payee_pseudonym"] | "").substring(5, 17), "Release, then hold 3s");
}

void appendChunk(String& buffer, char value) {
    if (value == '\n') { if (buffer.length()) acceptPacket(buffer); buffer = ""; }
    else if (value != '\r') { if (buffer.length() >= MAX_PACKET) { buffer = ""; pending = false; show("Packet too large"); } else buffer += value; }
}

class ReceiveCallbacks : public NimBLECharacteristicCallbacks {
    void onWrite(NimBLECharacteristic* characteristic, NimBLEConnInfo&) override {
        auto value = characteristic->getValue();
        if (value.size() > 240) return;
        BleChunk chunk;
        chunk.length = value.size();
        memcpy(chunk.bytes, value.data(), chunk.length);
        xQueueSend(incoming, &chunk, 0);
    }
};

void setup() {
    Serial.begin(115200);
    Wire.begin(4, 5);
    display.begin(SSD1306_SWITCHCAPVCC, 0x3C);
    pinMode(BUTTON_PIN, INPUT_PULLUP);
    incoming = xQueueCreate(12, sizeof(BleChunk));
    NimBLEDevice::init("EarlyTrace-Key");
    NimBLEDevice::setMTU(247);
    Preferences preferences;
    preferences.begin("earlytrace", false);
    if (preferences.getBytesLength("signing-key") == 32) preferences.getBytes("signing-key", privateKey, 32);
    else { esp_fill_random(privateKey, 32); preferences.putBytes("signing-key", privateKey, 32); }
    preferences.end();
    Ed25519::derivePublicKey(publicKey, privateKey);
    deviceId = "device_";
    for (int index = 0; index < 16; ++index) { char hex[3]; snprintf(hex, sizeof(hex), "%02x", publicKey[index]); deviceId += hex; }
    pinned = decodeBase64(TRAIL_SERVER_KEY_B64, serverKey, sizeof(serverKey), 32);
    JsonDocument identity;
    identity["device_id"] = deviceId;
    identity["public_key_b64"] = encodeBase64(publicKey, 32);
    String identityPacket;
    serializeJson(identity, identityPacket);
    Serial.println(identityPacket);
    auto* server = NimBLEDevice::createServer();
    auto* service = server->createService(SERVICE_UUID);
    auto* receiver = service->createCharacteristic(RECEIVE_UUID, NIMBLE_PROPERTY::WRITE);
    receiver->setCallbacks(new ReceiveCallbacks());
    responses = service->createCharacteristic(RESPONSE_UUID, NIMBLE_PROPERTY::READ | NIMBLE_PROPERTY::NOTIFY);
    service->createCharacteristic(IDENTITY_UUID, NIMBLE_PROPERTY::READ)->setValue(identityPacket.c_str());
    service->start();
    auto* advertising = NimBLEDevice::getAdvertising();
    advertising->addServiceUUID(SERVICE_UUID);
    advertising->start();
    show("EARLYTRACE KEY", pinned ? "Await signed review" : "Server key not pinned", "Prototype / advisory");
}

void loop() {
    while (Serial.available()) appendChunk(serialInput, Serial.read());
    BleChunk chunk;
    while (xQueueReceive(incoming, &chunk, 0) == pdTRUE) for (int index = 0; index < chunk.length; ++index) appendChunk(bleInput, chunk.bytes[index]);
    if (!pending) return;
    if (millis() - receivedAt > 120000) { pending = false; show("Challenge expired"); return; }
    if (digitalRead(BUTTON_PIN) == HIGH) { released = true; holdStarted = 0; return; }
    if (!released) return;
    if (!holdStarted) holdStarted = millis();
    if (millis() - holdStarted < 3000) return;
    String message = signedMessage + "\nACKNOWLEDGE_REVIEW";
    uint8_t signature[64];
    Ed25519::sign(signature, privateKey, publicKey, message.c_str(), message.length());
    JsonDocument response;
    response["challenge_id"] = challengeId;
    response["signature_b64"] = encodeBase64(signature, 64);
    String packet;
    serializeJson(response, packet);
    Serial.println(packet);
    responses->setValue(packet.c_str());
    responses->notify();
    pending = false;
    show("Review acknowledged", "Not a payment release");
}