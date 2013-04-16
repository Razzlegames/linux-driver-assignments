
#ifndef CSE5361_H
#define CSE5361_H 

#include <linux/types.h>

/// Attempt to use an unreserved IP protocol number
#define IPPROTO_CSE536  234
#define CSE536_MAJOR 234

//-------------------------------------------------------
// Print macros
//-------------------------------------------------------

#define ERROR(s, ...) \
  printk(KERN_ERR "%s:%d ERROR: " s, __FILE__, __LINE__, ##__VA_ARGS__); \


#define DEBUG(s, ...) \
  printk(KERN_DEBUG "%s:%d DEBUG: " s, __FILE__, __LINE__, ##__VA_ARGS__); \


//-------------------------------------------------------
//  Custom Data types/structs
//-------------------------------------------------------

enum
{
  IP_RECORD=1, DATA_RECORD=2,
};


typedef enum 
{

  UNKNOWN_MESSAGE = -1,
  ACK_MESSAGE = 0,
  EVENT_MESSAGE = 1,
}MessageType;

typedef struct AckMessage
{

  /// Record ID
  uint32_t record_id;

  /// Address we will receive ack from
  __be32 rec_address;

  /// The counter value we had when we sent the event 
  ///   Message (the ack will have this)
  uint32_t counter;

}AckMessage;


typedef struct EventMessage
{

  /// Record ID
  uint32_t record_id;

  /// Source IP
  __be32 source_ip;

  /// counter
  uint32_t counter;

  /// data
  uint8_t data[0xFF-sizeof(uint32_t)-sizeof(__be32) - 
    sizeof(uint32_t)];

}EventMessage;

#endif /* CSE5361_H */
