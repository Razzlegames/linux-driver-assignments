
#ifndef CSE5361_H
#define CSE5361_H 

#include <linux/types.h>

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

typedef struct 
{
  /// Address we will receive ack from
  __be32 rec_address;

  /// The counter value we had when we sent the event 
  ///   Message (the ack will have this)
  unsigned int counter;

}MessageAckRecord;


typedef struct 
{
  /// Record ID
  unsigned int record_id;

  /// Source IP
  __be32 source_ip;

  /// counter
  unsigned int counter;

  /// data
  unsigned char data[244];

}EventMessage;

#endif /* CSE5361_H */
