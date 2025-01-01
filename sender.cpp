
#include <Arduino.h>
#include <ATTinyCore.h>
#include <SPI.h>
#include <LoRa.h>
#include <Crypto.h>
#include <AES.h>
#include <CTR.h>
#include <string.h>
#include <avr/sleep.h>
#include <avr/wdt.h>

// ATMEL ATTINY84 / ARDUINO
//
//                           +-\/-+
//                     VCC  1|    |14  GND
//             (D  0)  PB0  2|    |13  PA0  (D 10)        AREF
//             (D  1)  PB1  3|    |12  PA1  (D  9)
//             (D 11)  PB3  4|    |11  PA2  (D  8)
//  PWM  INT0  (D  2)  PB2  5|    |10  PA3  (D  7)
//  PWM        (D  3)  PA7  6|    |9   PA4  (D  6)
//  PWM        (D  4)  PA6  7|    |8   PA5  (D  5)        PWM
//                           +----+

// these arrays map port names (e.g. port B) to the
// appropriate addresses for various functions (e.g. reading
// and writing)
#define statusled 2    // LED for control
#define irled 1        // power for ir-led of proximity sensor (invisible)
#define irdiode 0      // power in for diode in proximity sensor
#define irsens PA0     //adc pin (connect to output of sensor)
#define csPin 7        // LoRa radio chip select
#define resetPin -1    // LoRa radio reset // -1 for not in use
#define dio0Pin 3      // change for your board; must be a hardware interrupt pin
#define freq 868700000 // LoRa used frequency 868 MHz
#define SF 7           // LoRa used spreadingFactor // ranges from 6-12,default 7 see API docs
#define bw 125E3       // LoRa signal bandwidth in Hz, defaults to 125E3
#define sw 0x12        // LoRa SyncWord ranges from 0-0xFF, default 0x12, see LoRa API docs

// define a threshold for your mailbox.
#define THRESHOLD 15

#define MAX_PLAINTEXT_SIZE 82
#define MAX_CIPHERTEXT_SIZE 82

byte key[16] = {0x01, 0x02, 0x0b, 0x5b, 0xc6, 0x6e, 0xa5, 0xa3, 0xfa, 0x1a, 0xf7, 0xf3, 0x8d, 0xc3, 0x7a, 0xbc}; // The very secret key
byte iv[16] = {0xa7, 0x8a, 0x23, 0x2d, 0xed, 0x1c, 0x77, 0xd8, 0xfd, 0xab, 0x8b, 0x13, 0xc4, 0x8d, 0xb1, 0xf3};
byte ciphertext[MAX_CIPHERTEXT_SIZE] = {0};
uint16_t msgCount = 0; // count of outgoing messages
long vbat = 0;
bool post = 0;
bool post_old = 0;
int sleepCycles = 1;

CTR<AESTiny128> ctr;

/*--------------------------------------------------------------------------------
                                    Setup
--------------------------------------------------------------------------------*/
void setup()
{
  Serial.begin(9600); // TX is AIN0, RX is AIN1
  pinMode(irled, OUTPUT);
  pinMode(irdiode, OUTPUT);
  pinMode(statusled, OUTPUT);

  LoRa.setPins(csPin, resetPin, dio0Pin); // set CS, reset, IRQ pin

  if (!LoRa.begin(freq))
  { // initialize radio at "freq" MHz
    //Serial.println("LoRa init fail");
    while (true)
      ; // if failed, do nothing
  }
  //LoRa.setSpreadingFactor(SF);          // set spreadingFactor
  //LoRa.setSignalBandwidth(bw);          // set signal bandwidth
  LoRa.setSyncWord(sw); // set SyncWord
  //Serial.println("LoRa init");

  //Serial.println("Connected");
}

/*--------------------------------------------------------------------------------
                          Überprüfung auf Briefkasteninhalt
--------------------------------------------------------------------------------*/
void checkLetter()
{
  digitalWrite(irled, HIGH);
  digitalWrite(irdiode, HIGH);
  unsigned int measure;
  for (int i = 0; i < 3; i++)
  {
    delay(5);
    measure += analogRead(irsens);
  }
  measure = measure / 3;
  digitalWrite(irled, LOW);
  digitalWrite(irdiode, LOW);

  if (measure > THRESHOLD)
  {
    post = 1;
  }
  else
  {
    post = 0;
  }
}

/*--------------------------------------------------------------------------------
                          Batteriespannung ermitteln
--------------------------------------------------------------------------------*/
void getVbat()
{
  // Select ADC inputs
  // bit    76543210
  // REFS = 00       = Vcc used as Vref
  // MUX  =   100001 = Single ended, 1.1V (Internal Ref) as Vin
  ADMUX = _BV(MUX5) | _BV(MUX0); // oder	ADMUX = 0b00100001;
  /*
		After switching to internal voltage reference the ADC requires a settling time of 1ms before
		measurements are stable. Conversions starting before this may not be reliable. The ADC must
		be enabled during the settling time.
	*/
  delay(2);
  /*
		The first conversion after switching voltage source may be inaccurate, and the user is advised to discard this result.
	*/
  ADCSRA |= _BV(ADSC); // Start a conversion
  while (bit_is_set(ADCSRA, ADSC))
    ;   // Wait for 1st conversion to be ready...
        //..and ignore the result
  uint8_t low = ADCL;
  uint8_t high = ADCH;
  uint16_t vbat = (high << 8) | low; // 0<= result <=1023
  vbat = (1125300L / vbat);          // 1125300 = 1.1 x 1023 x 1000
}

/*--------------------------------------------------------------------------------
                           Json String generierung
--------------------------------------------------------------------------------*/
// {"Sensor":"MBox","VBat":4066345,"Post":1,"msg":32452,"RSSI":"xxx"}
// "{\"Sensor\":\"MBox\",\"VBat\":4066345,\"Post\":1,\"msg\":32452,\"RSSI\":\"xxx\"}"
String json_data_prep()
{
  String json = "{\"Sensor\":\"MBox\",\"VBat\":";
  json += (long)vbat;
  json += ",\"Post\":";
  json += (bool)post;
  json += ",\"msg\":";
  json += (unsigned int)msgCount;
  json += ",\"RSSI\":\"xxx\"}";

  return json;
}

/*--------------------------------------------------------------------------------
                                  Encode Massage
--------------------------------------------------------------------------------*/
void encode_msg(String json)
{
  byte plaintext[MAX_PLAINTEXT_SIZE] = {0};

  for (uint8_t i = 0; i <= json.length(); i++)
  {
    plaintext[i] = (byte)json[i];
  }

  ctr.clear();
  ctr.setKey(key, ctr.keySize());
  ctr.setIV(iv, ctr.ivSize());

  memset(ciphertext, 0xBA, sizeof(ciphertext));

  ctr.encrypt(ciphertext, plaintext, sizeof(plaintext));
}

/*--------------------------------------------------------------------------------
                                LoRa Massage senden
--------------------------------------------------------------------------------*/
void sendMessage(byte *outgoing)
{
  // send packet
  LoRa.beginPacket(); // start packet
  //LoRa.print(outgoing); // add payload
  LoRa.write(outgoing, sizeof(ciphertext));
  LoRa.endPacket(); // finish packet and send it
  msgCount++;       // increment message ID
  LoRa.sleep();
}

/*--------------------------------------------------------------------------------
                                      Sleep
--------------------------------------------------------------------------------*/
void setSleeptime(int time)
{
  sleepCycles = time / 8;
}

void gotoSleep()
{
  //disable ADC
  ADCSRA &= ~(1 << ADEN);
  // WD Reset Flag to 0 (p. 45)
  bitClear(MCUSR, WDRF);
  // WD Change Enable (p. 46)
  bitSet(WDTCSR, WDCE);
  // WD Enable (p. 46)
  bitSet(WDTCSR, WDE);
  // create 8 second WD Timer Prescaler
  // 1 0 0 1 means "8 seconds" (p. 47)
  bitSet(WDTCSR, WDP3);
  bitClear(WDTCSR, WDP2);
  bitClear(WDTCSR, WDP1);
  bitSet(WDTCSR, WDP0);
  // WD Interrupt Enable (p. 45)
  bitSet(WDTCSR, WDIE);

  for (int i = 0; i < sleepCycles; i++)
  {
    set_sleep_mode(SLEEP_MODE_PWR_DOWN);
    sleep_mode(); // Start sleeping
  }

  wdt_disable();
  // enable ADC again
  ADCSRA |= (1 << ADEN);
}

/*--------------------------------------------------------------------------------
                                    Main Loop
--------------------------------------------------------------------------------*/
void loop()
{
  checkLetter();

  if (post_old != post) // Wenn Wert geändert, dann senden
  {
    getVbat();
    encode_msg(json_data_prep());
    sendMessage(ciphertext);
    post_old = post;
  }

  if (post == true)
  {
    digitalWrite(statusled, HIGH);
    Serial.println("1");
  }
  else
  {
    digitalWrite(statusled, LOW);
    Serial.println("0");
  }

  setSleeptime(900); // Sleeptime in seconds; teilbar durch 8 seconds
  gotoSleep();      // Sleep for x sleepCycles; 1 sleepCycles = 8 seconds
}
