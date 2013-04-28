
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
#define MAX_IP_STR 13

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


typedef struct MessageHeader
{

  /// Record ID
  uint32_t record_id;

  /// counter
  uint32_t final_clock;

  /// counter
  uint32_t orig_clock;

  /// Source IP
  __be32 source_ip;

  /// Dest IP
  __be32 dest_ip;

}MessageHeader;

typedef struct Message
{

  MessageHeader header;
  /// data
  uint8_t data[0xFF-sizeof(MessageHeader)];

}Message;

#endif /* CSE5361_H */
