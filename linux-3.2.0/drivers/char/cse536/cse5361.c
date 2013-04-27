#include <linux/module.h>
#include <linux/fs.h>

#include <crypto/aead.h>
#include <crypto/authenc.h>
#include <linux/err.h>
#include <linux/module.h>
#include <net/ip.h>
#include <net/xfrm.h>
#include <net/esp.h>
#include <linux/scatterlist.h>
#include <linux/kernel.h>
#include <linux/pfkeyv2.h>
#include <linux/rtnetlink.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/in6.h>
#include <net/icmp.h>
#include <net/protocol.h>
#include <net/udp.h>
#include <linux/in.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include "cse5361.h"
static int debug_enable = 0;
module_param(debug_enable, int, 0);
MODULE_PARM_DESC(debug_enable, "Enable module debug mode.");
struct file_operations cse536_fops;

#define MAX_SEND_RETRY 1

unsigned char* rec_buffer = NULL;

#define MAX_BUFFER_SIZE 256
static inline void check_buffer_size_compile(void)
{ 
  BUILD_BUG_ON(sizeof(Message) != MAX_BUFFER_SIZE);
}

/**
 *  Create a linked list to keep track of all buffers
 *   received on the network
 */
struct receive_list
{
  unsigned char buffer[MAX_BUFFER_SIZE];
  size_t size;
  struct receive_list* next;
};

//-------------------------------------------------------
//  Function prototypes
//-------------------------------------------------------
/// Make sure writes/reads are synced to this list
static DEFINE_MUTEX(receive_list_mutex);
/// The head of the linked list to receive data
static struct receive_list* receive_list_head = NULL;
static struct receive_list* receive_list_tail = NULL;
static int list_length = 0;

//static void sendPacket(size_t data_size, const char* buffer,
//    const char* SADDR_STRING,
//    const char* DADDR_STRING);

void processEventPacket(Message* data, unsigned int len);
static void sendPacketU32(size_t data_size, 
    const uint8_t* buffer,
    __be32 saddr, __be32 daddr);
static void sendPacketAndWaitForAck(Message* message);

static void cse536_err(struct sk_buff *skb, u32 info);
int cse536_receive(struct sk_buff* skb);
static __be32 getSourceAddr(void);
void addBuffer(uint8_t* buffer, size_t size);
struct receive_list* allocateBuffer(unsigned char* buffer, 
    size_t size);
static struct receive_list* getOldestBufferNotRead(void);
static void deleteBuffers(void);
static int waitForACK(void);
int processAckPacket(Message* data);
void resetAckRecord(void);
void printMessage(const Message* message);

//static struct receive_list* last_read = NULL;
//static void clearOldBuffers(void);

DEFINE_SPINLOCK(receive_list_lock);
DEFINE_SPINLOCK(create_ack_lock);
DEFINE_SPINLOCK(counter_lock);
struct semaphore read_semaphore;
struct semaphore write_semaphore;
struct semaphore ack_semaphore;

/// Current counter value for this protocol
uint32_t counter = 0xFFFFFF;

/// Current ack we are waiting on
Message ack_record;

const unsigned int MSECONDS_TO_WAIT = 5*1000;

//************************************************************************
struct receive_list* allocateBuffer(unsigned char* buffer, 
    size_t size)
{

  struct receive_list* r =  (struct receive_list*)kmalloc(
      sizeof(struct receive_list),GFP_ATOMIC );

  if(r == NULL)
  {
    ERROR("Could not allocate space for receive list!\n");
    return NULL;
  }

  // Zero out entire mem for link entry
  memset(r, 0, sizeof(struct receive_list));

  if(size > MAX_BUFFER_SIZE)
  {
    size = MAX_BUFFER_SIZE;
    DEBUG("Adjusted size to: %zu\n", size);
  }
  memcpy(r->buffer, buffer, size);
  r->size = size;
  r->next = NULL;
  return r;
}


//************************************************************************
static struct receive_list* getOldestBufferNotRead(void)
{
  struct receive_list* h = NULL;
  struct receive_list* to_return = NULL;

  spin_lock_bh(&receive_list_lock);

  h = receive_list_head;
  if(h == NULL)
  {
    //DEBUG("head of list was null!\n");

    //spin_unlock_bh(&receive_list_lock);
    to_return = NULL;
    goto endgetOldestBufferNotRead;
  }

  //receive_list_head = h->next;
  to_return = receive_list_head;
  receive_list_head = receive_list_head->next;

  DEBUG("Returning found buffer: %p!\n", to_return);

endgetOldestBufferNotRead:
  spin_unlock_bh(&receive_list_lock);
  return to_return;

}

//************************************************************************
/**
 *  Delete all linked lists of received packets
 */
static void deleteBuffers(void)
{

  struct receive_list* to_delete = NULL;
  struct receive_list* h = NULL;
  int i = 0;

  spin_lock_bh(&receive_list_lock);

  h = receive_list_head;
  DEBUG("Delete all buffers in module:\n");
  while(h != NULL)
  {
    to_delete = h;
    h = h->next;
    kfree(to_delete);
    DEBUG("Deleted buffer: %d\n", i);
    i++;
  }
  receive_list_head = NULL;

  up(&read_semaphore);
  spin_unlock_bh(&receive_list_lock);
}

//************************************************************************
void addBuffer(uint8_t* buffer, size_t size)
{

  DEBUG("Adding packet[%zu]\n", size);

  spin_lock_bh(&receive_list_lock);

  if(receive_list_head == NULL)
  {
    receive_list_head = allocateBuffer(buffer, size);
    receive_list_tail = receive_list_head;
    DEBUG("Allocated %d buffer on head\n", list_length);
    list_length++;

    goto endAddBuffer;
  }
  if(receive_list_tail == NULL)
  {
    ERROR("receive_list_tail is NULL! "
        "Should never happen!\n");

    goto endAddBuffer;
  }

  receive_list_tail->next = allocateBuffer(buffer, size);
  receive_list_tail = receive_list_tail->next;
  DEBUG("Allocated %d buffer on tail\n", list_length);
  list_length++;

endAddBuffer:
  spin_unlock_bh(&receive_list_lock);
  return;
}
//************************************************************************
static const struct net_protocol cse536_protocol = {
  .handler	=	cse536_receive,
  .err_handler	=	cse536_err,
  .no_policy	=	1,
  .netns_ok	=	1,
};

//************************************************************************
/**
 *  Reset ack record
 */

void resetAckRecord(void)
{

  memset(&ack_record, 0, sizeof(ack_record));
  ack_record.header.record_id = UNKNOWN_MESSAGE;
  ack_record.header.orig_clock = 0xFFFF;
}

//************************************************************************
/**
 *  Process event packet received
 */
int processAckPacket(Message* data)
{

  DEBUG("------------------------------------\n");
  DEBUG("Process ACK packet!\n");
  DEBUG("------------------------------------\n");


  if(data == NULL)
  {
    ERROR("Ack message was null!\n");
    return -1;
  }

  // See if this ACK is the driod we're looking for
  //   If so notify (up) the user process ACK was received
  spin_lock_bh(&create_ack_lock);
  if(data->header.record_id == ACK_MESSAGE &&
      data->header.orig_clock == ack_record.header.orig_clock &&
      data->header.source_ip == ack_record.header.dest_ip)
  {

    resetAckRecord();
    // Let the user process wake up since the ack was 
    //   received
    up(&ack_semaphore);

  }
  else
  {
    DEBUG("------------------------------------\n");
    ERROR("Ack received doesn't match ack waiting for...");
    DEBUG("------------------------------------\n");
    DEBUG("Ack waiting: \n");
    printMessage(&ack_record);
    DEBUG("Ack received: \n");
    printMessage(data);
  }
  ack_record.header.orig_clock = counter;
  spin_unlock_bh(&create_ack_lock);
  return 0;

}

//************************************************************************
/**
 *  Process event packet received
 */

void processEventPacket(Message* message, unsigned int len)
{

  Message* ack_to_send = NULL;
  __be32 saddr = getSourceAddr();

  DEBUG("------------------------------------\n");
  DEBUG("Process EVENT packet!\n");
  DEBUG("------------------------------------\n");

  if(message == NULL)
  {
    ERROR("Event message was null!\n");
    return;
  }

  if(sizeof(message) < len)
  {
    ERROR("SK buff len: %u sent was smaller than total "
        "sizeof(Message): %zu ! Something strange "
        "might happen!\n", len, sizeof(message));
  }

  ack_to_send = (Message*)kmalloc( sizeof(*ack_to_send), GFP_ATOMIC);

  spin_lock_bh(&counter_lock);
  if(message->header.orig_clock > counter)
  {
    DEBUG("Updating counter/clock: %d, to %d\n", 
        counter, message->header.orig_clock);

    counter = message->header.orig_clock;
  }
  spin_unlock_bh(&counter_lock);

  *ack_to_send = *message;
  ack_to_send->header.dest_ip = message->header.source_ip;
  ack_to_send->header.source_ip = saddr;

  // Send Ack
  sendPacketU32(sizeof(*ack_to_send) , 
      (uint8_t*)ack_to_send, 
      ack_to_send->header.source_ip, 
      ack_to_send->header.dest_ip);

  addBuffer((uint8_t*)message, len);
  kfree(ack_to_send);

}

//************************************************************************
/**
 *  Receive packets on the new protocol
 */
int cse536_receive(struct sk_buff* skb)
{

  unsigned char* transport_data = NULL;
  uint32_t record_id = UNKNOWN_MESSAGE;
  Message* message = NULL;

  DEBUG("------------------------------------\n");
  DEBUG("ENTERED Received packet\n");
  DEBUG("------------------------------------\n");

  if(skb == NULL)
  {
    ERROR("packet received was NULL!\n");
    return -1;
  }

  transport_data = skb_transport_header(skb);
  if(transport_data == NULL)
  {
    ERROR("Packet transport layer was NULL!\n");
    return -1;
  }

  DEBUG("Received an IP packet! skb->data_len[%zu]\n",
      (size_t)skb->data_len);
  DEBUG("skb->end[%zu]\n",
      (size_t)skb->end);
  DEBUG("skb->len-sizeof(struct iphdr)[%zu]\n",
      (size_t)(skb->len-sizeof(struct iphdr)));
  DEBUG("skb->len[%zu]\n",
      (size_t)skb->len);
  DEBUG("skb->tail[%zu]\n",
      (size_t)skb->tail);
  DEBUG("skb->mac_header[%zu]\n",
      (size_t)skb->mac_header);
  DEBUG("skb->head[%zu]\n",
      (size_t)skb->head);
  DEBUG("transport_data[%zu]\n",
      (size_t)transport_data);

  message = (Message*)transport_data;
  record_id = message->header.record_id;
  DEBUG("Message received: %s\n", message->data);
  printMessage(message);

  if(record_id == ACK_MESSAGE)
  {
    processAckPacket(message);
  }
  else if(record_id == EVENT_MESSAGE)
  {
    processEventPacket(message, skb->len);
  }
  else
  {
    ERROR("Unknown record type received!: %d\n",
        record_id);
    return -1;
  }

  return 0;

}


//************************************************************************
static int cse536_open(struct inode *inode, struct file *file)
{
  printk("cse536_open: successful\n");
  return 0;
}

//************************************************************************
static int cse536_release(struct inode *inode, struct file *file)
{
  printk("cse536_release: successful\n");
  return 0;
}

//************************************************************************
static ssize_t cse536_read(struct file *file, char *buf, size_t count,
    loff_t *ptr)
{

  struct receive_list* read_entry = NULL;
  size_t read_amount = 0;

  down(&read_semaphore);

  //DEBUG("entered read! count: %zu\n", count);

  read_entry = getOldestBufferNotRead();
  if(read_entry == NULL)
  {
    read_amount = 0;
    goto endCse536Read;
  }

  if(MAX_BUFFER_SIZE > count)
  {
    read_amount = count;
  }
  else
  {
    read_amount = MAX_BUFFER_SIZE;
  }

  memcpy(buf, read_entry->buffer, read_amount);
  printk("cse536_read: returning %zu bytes\n", read_amount);

endCse536Read:
  up(&read_semaphore);
  return read_amount;
}

//************************************************************************
/**
 *  Find source address
 */
static __be32 getSourceAddr(void)
{

  __be32 saddr = 0;

  // find the source addr
  struct net_device* eth0 = dev_get_by_name(&init_net, "eth0");
  struct in_device* ineth0 = in_dev_get(eth0);
  int i = 0;

  for_primary_ifa(ineth0)
  {

    if(i == 0)
    {
      saddr = ifa->ifa_address;
    }
    i++;
  }endfor_ifa(ineth0);

  return saddr;

}

//***************************************************************
/**
 *  Check to see what message type we're dealing with.
 */

MessageType getMessageType(Message* message, size_t count)
{

  uint32_t message_type = 0;

  if(message == NULL)
  {
     ERROR("message was NULL!\n");
     return UNKNOWN_MESSAGE;
  }

  message_type = message->header.record_id;
  if(count < 4)
  {
    return UNKNOWN_MESSAGE;
  }

  switch(message_type)
  {
    case ACK_MESSAGE:
      DEBUG("------------------------------------\n");
      DEBUG("Found ACK message\n");
      DEBUG("------------------------------------\n");
      printMessage(message);
      break;
    case EVENT_MESSAGE:
      DEBUG("------------------------------------\n");
      DEBUG("Found EVENT message\n");
      DEBUG("------------------------------------\n");
      printMessage(message);
      break;
    default:
      DEBUG("------------------------------------\n");
      ERROR("!!!!! Cannot find message type for packet!\n");
      DEBUG("------------------------------------\n");
      return UNKNOWN_MESSAGE;
  }
  return message_type;
}

//************************************************************************
/**
 *   Wait for ACK packet from receiver or timeout
 */

static int waitForACK(void)
{

  long jiffies_timeout = msecs_to_jiffies(MSECONDS_TO_WAIT);

  int ack_received = 0;

  // Wait till TCP thread releases us on ACK
  //    (or timeout is exceeded)
  int result = down_timeout(&ack_semaphore, jiffies_timeout);

  spin_lock_bh(&create_ack_lock);
  if(result == -ETIME)
  {
    DEBUG("Ack never received!!! For counter: %d\n",
        ack_record.header.orig_clock);
  }
  else
  {
    ack_received = 1;
  }
  spin_unlock_bh(&create_ack_lock);

  return ack_received;
}

//************************************************************************
void printMessage(const Message* message)
{


  /// Record ID
  DEBUG(" record_id: %u\n", message->header.record_id);

  /// counter
  DEBUG(" final_clock: %u\n", message->header.final_clock);

  /// counter
  DEBUG(" orig_clock: %u\n", message->header.orig_clock);

  /// Source IP
  DEBUG("__be32 source_ip: %u\n", message->header.source_ip);

  /// Dest IP
  DEBUG(" dest_ip: %u\n", message->header.dest_ip);


  DEBUG(" data: %s\n", message->data);

}

//************************************************************************
static ssize_t cse536_write(struct file *file, const char *buf,
    size_t count, loff_t * ppos)
{

  __be32 saddr = getSourceAddr();

  // Message container for convenience
  //   (allocated in Kernel mem)
  Message* message = NULL;

  // Detect issues with invalid messages
  MessageType message_type = UNKNOWN_MESSAGE;

  // LOCK writing in dev to one user at a time
  down(&write_semaphore);

  DEBUG("------------------------------------\n");
  DEBUG("ENTERED char driver Write\n");
  DEBUG("------------------------------------\n");

  if(buf == NULL)
  {

    ERROR("buffer to send was null!!\n");
    count = 0;
    goto endCse536Write;
  }
  if(count > MAX_BUFFER_SIZE)
  {
    ERROR("Received a message size, %zu, "
        "that is longer than the "
        "max allowed by this protocol: %d\n",
        count, MAX_BUFFER_SIZE);
    printMessage((Message*)buf);
    count = 0;
    goto endCse536Write;
  }

  // Copy to temp buffer to work on
  message = 
    (Message*)kmalloc(sizeof(*message), GFP_ATOMIC);

  if(message == NULL)
  {
    ERROR("Could not malloc space for message!\n");
    goto endCse536Write;
  }

  memcpy(message, buf, count);

  message_type = getMessageType(message, count);
  if(message_type != EVENT_MESSAGE)
  {
    ERROR("Not writing event message from user app!\n");
    goto endCse536Write;
  }

  DEBUG("cse536_write: accepting %zd bytes\n", count);

  // Set the source ip here 
  //    (don't have user app send this. Will crash if wrong)
  message->header.source_ip = saddr;

  DEBUG("source addr: 0x%04x\n", message->header.source_ip);
  DEBUG("destination addr: 0x%04x\n", message->header.dest_ip);
  DEBUG("data_buff:%s\n", message->data);

  // Reading counter
  spin_lock_bh(&counter_lock);

  // Create ack message, we're looking for
  spin_lock_bh(&create_ack_lock);
  // Set the original clock in the message
  message->header.orig_clock = counter;
  ack_record = *message;
  ack_record.header.record_id = ACK_MESSAGE;

  spin_unlock_bh(&create_ack_lock);
  spin_unlock_bh(&counter_lock);

  DEBUG("clock:%d\n", message->header.orig_clock);

  // Send and wait for response
  sendPacketAndWaitForAck(message);

endCse536Write:
  kfree(message);

  up(&write_semaphore);
  return count;

}

//************************************************************************
static long cse536_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
  printk("cse536_ioctl: cmd=%d, arg=%ld\n", cmd, arg);
  return 0;
}

//************************************************************************
static int __init cse536_init(void)
{

  int ret;
  printk("cse536 module Init - debug mode is %s\n",
      debug_enable ? "enabled" : "disabled");
  ret = register_chrdev(CSE536_MAJOR, "cse5361", &cse536_fops);
  if (ret < 0) 
  {
    printk("Error registering cse536 device\n");
    return ret;
  }

  ret = inet_add_protocol(&cse536_protocol, IPPROTO_CSE536);
  if(ret < 0)
  {
    ERROR("Could not register cse536_protocol!");
    inet_del_protocol(&cse536_protocol, IPPROTO_CSE536);
    return ret;
  }

  sema_init(&read_semaphore, 1);
  sema_init(&write_semaphore, 1);
  sema_init(&ack_semaphore, 1);

  printk("cse536: registered module successfully!\n");

  return 0;

}

//************************************************************************
static void __exit cse536_exit(void)
{
  int ret = inet_del_protocol(&cse536_protocol, IPPROTO_CSE536);
  if(ret < 0)
  {
    ERROR("Could not unregister protocol!\n");
  }
  unregister_chrdev(CSE536_MAJOR, "cse5361"); 

  deleteBuffers();
  printk("cse536 module Exit\n");
}

//************************************************************************
/**
 *  Get the mac address for a ipv4 addr
 */
void getMacAddresses(__be32 saddr,__be32 daddr, 
    struct sk_buff* skb)
{

  struct rtable* rt = NULL;
  struct net* net = &init_net;
  //struct ethhdr* eth = NULL;

  DEBUG("getting MAC addresses from routing table\n");
  rt = ip_route_output(net, daddr, saddr, 0, 0);
  skb_dst_set(skb, &rt->dst);
  DEBUG("Destination found: 0x%08lx\n", 
      (unsigned long)&rt->dst);

  //  eth = eth_hdr(skb);
  //  DEBUG("Destination MAC:%02x:%02x:%02x:%02x:%02x:%02x\n",
  //      eth->h_dest[0],
  //      eth->h_dest[1],
  //      eth->h_dest[2],
  //      eth->h_dest[3],
  //      eth->h_dest[4],
  //      eth->h_dest[5]);

}

//************************************************************************
/**
 *  Send packet and wait for ACK
 */

static void sendPacketAndWaitForAck(Message* message)
{

  int ack_received = 0;
  int send_count = 0;

  // Resend for MAX_SEND_RETRY if ack not received
  while(!ack_received && send_count <= MAX_SEND_RETRY)
  {

    sendPacketU32(sizeof(Message) , message->data, 
        message->header.source_ip, message->header.dest_ip);

    // It's a EVENT_MESSAGE so wait for ack or timeout
    ack_received = waitForACK();
    send_count++;
  }

  // Increment counter since packet sent
  spin_lock_bh(&counter_lock);
  counter++;
  spin_unlock_bh(&counter_lock);

  // Reset ack record since we're no longer waiting on ACK
  //   (it either timed out or was received at this point)
  spin_lock_bh(&create_ack_lock);
  resetAckRecord();
  spin_unlock_bh(&create_ack_lock);


}

//************************************************************************
/**
 *  Send out a raw packet using the IP layer.
 *
 *  @param data_size size of @p buffer
 *  @param buffer data to send 
 *  @param saddr ip source address
 *  @param daddr ip dest address
 */

static void sendPacketU32(size_t data_size, 
    const uint8_t* buffer,
    __be32 saddr, __be32 daddr)
{

  const int LENGTH = 1500 + sizeof(struct iphdr) + data_size;
  struct sk_buff* skb = alloc_skb(LENGTH, GFP_ATOMIC);
  struct iphdr* ip_header = NULL;
  unsigned char* transport_data = NULL;
  int err = 0;

  DEBUG("Sending data: buffer[%zd] "
      "to: %04x, from: %04x\n", data_size, daddr,
      saddr);

  if(skb == NULL)
  {

    ERROR("Could not allocate sk_buff!\n");
    return;
  }
  skb_reserve(skb, sizeof(*ip_header)+
      sizeof(struct udphdr));

  // Save off all the payload data
  DEBUG("Saving payload data\n");
  transport_data = skb_put(skb, data_size);

  //skb_reset_transport_header(skb);
  //transport_data = skb_transport_header(skb);
  //memcpy(transport_data, buffer, data_size);
  skb->csum = csum_and_copy_from_user(buffer, 
      transport_data, data_size, 0, &err);
  if(err)
  {
    ERROR("Could not load payload data!\n");
  }
  DEBUG("Done saving payload data\n");

  // Create space in sk_buff for iphdr
  DEBUG("Creating space in sk_buff for iphdr\n");
  skb_push(skb, sizeof(*ip_header));
  skb_reset_network_header(skb);
  DEBUG("Done Creating space in sk_buff for iphdr\n");

  // Populate IP header
  DEBUG("Creating ip_header\n");
  ip_header = ip_hdr(skb);

  ip_header->version = 4;
  ip_header->ihl = 5;
  ip_header->tos = 0;
  ip_header->tot_len = htons(data_size + sizeof(ip_header));
  ip_header->id = 0;
  ip_header->frag_off = 0;
  ip_header->ttl = 64;
  ip_header->protocol = IPPROTO_CSE536;
  ip_header->check = 0;

  ip_header->saddr = saddr;
  ip_header->daddr = daddr;
  ip_header->check = ip_fast_csum((unsigned char*)ip_header,
      ip_header->ihl);
  DEBUG("Done Creating ip_header\n");

  DEBUG("Creating mac header...\n");

  //eth = (struct ethhdr*) skb_push(skb, ETH_HLEN);
  //skb_reset_mac_header(skb);
  //skb->protocol = eth->h_proto = htons(ETH_P_IP);
  //memcpy(eth->h_source, init_net.dev_addr, ETH_ALEN);
  getMacAddresses(saddr, daddr, skb);
  DEBUG("Done Creating mac header...\n");

  DEBUG("Sending IP Packet!\n");
  ip_local_out(skb);
  DEBUG("Done Sending IP Packet!\n");

}

////************************************************************************
///**
// *  Send out a raw packet using the IP layer.
// *
// *  @param data_size size of @p buffer
// *  @param buffer data to send 
// *  @param SADDR_STRING ip source address
// *  @param DADDR_STRING ip source address
// */
//static void sendPacket(size_t data_size, const char* buffer,
//    const char* SADDR_STRING,
//    const char* DADDR_STRING)
//{
//
//  __be32 saddr = in_aton(SADDR_STRING);
//  __be32 daddr= in_aton(DADDR_STRING);
//  sendPacketU32(data_size, buffer, saddr, daddr);
//}

//***************************************************************
static void cse536_err(struct sk_buff *skb, u32 info)
{

  ERROR("Protocol error happened, code: %d\n", info);
}

//************************************************************************
struct file_operations cse536_fops = {
owner: THIS_MODULE,
       read: cse536_read,
       write: cse536_write,
       unlocked_ioctl: cse536_ioctl,
       open: cse536_open,
       release: cse536_release,
};

module_init(cse536_init);
module_exit(cse536_exit);

MODULE_AUTHOR("Kyle Luce");
MODULE_DESCRIPTION("cse536 Module");
MODULE_LICENSE("GPL");

