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

unsigned char* rec_buffer = NULL;

#define MAX_BUFFER_SIZE 256
static inline void check_buffer_size_compile(void)
{ 
  BUILD_BUG_ON(sizeof(EventMessage) != MAX_BUFFER_SIZE);
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

void processEventPacket(EventMessage* data, unsigned int len);
static void sendPacketU32(size_t data_size, 
    unsigned const char* buffer,
    __be32 saddr, __be32 daddr);

static void cse536_err(struct sk_buff *skb, u32 info);
int cse536_receive(struct sk_buff* skb);
static __be32 getSourceAddr(void);
void addBuffer(unsigned char* buffer, size_t size);
struct receive_list* allocateBuffer(unsigned char* buffer, 
    size_t size);
static struct receive_list* getOldestBufferNotRead(void);
static void deleteBuffers(void);
static void waitForACK(void);
int processAckPacket(AckMessage* data);
void resetAckRecord(void);

//static struct receive_list* last_read = NULL;
//static void clearOldBuffers(void);

DEFINE_SPINLOCK(rec_lock);
DEFINE_SPINLOCK(create_ack_lock);
DEFINE_SPINLOCK(counter_lock);
struct semaphore receive_semaphore;
struct semaphore ack_semaphore;

/// Current counter value for this protocol
unsigned int counter;

/// Current ack we are waiting on
AckMessage ack_record;

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

  //int i = 0;
  //mutex_lock(&receive_list_mutex);
  //spin_lock_bh(&rec_lock);
  //down(&receive_semaphore);

  h = receive_list_head;
  if(h == NULL)
  {
    //DEBUG("head of list was null!\n");

    //spin_unlock_bh(&rec_lock);
    to_return = NULL;
    goto endgetOldestBufferNotRead;
  }

  //receive_list_head = h->next;
  to_return = receive_list_head;
  receive_list_head = receive_list_head->next;

  DEBUG("Returning found buffer: %p!\n", to_return);

endgetOldestBufferNotRead:
  //up(&receive_semaphore);
  //spin_unlock_bh(&rec_lock);
  //mutex_unlock(&receive_list_mutex);
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

  down(&receive_semaphore);
  //spin_lock_bh(&rec_lock);

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

  up(&receive_semaphore);
  //spin_unlock_bh(&rec_lock);
}

//************************************************************************
void addBuffer(unsigned char* buffer, size_t size)
{

  DEBUG("Adding packet[%zu]\n", size);

  //spin_lock_bh(&rec_lock);
  //mutex_lock(&receive_list_mutex);
  down(&receive_semaphore);

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
  up(&receive_semaphore);
  //spin_unlock_bh(&rec_lock);
  //mutex_unlock(&receive_list_mutex);
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

  ack_record.record_id = UNKNOWN_MESSAGE;
  ack_record.counter = 0xFFFF;
}

//************************************************************************
/**
 *  Process event packet received
 */
int processAckPacket(AckMessage* data)
{

  if(data == NULL)
  {
    ERROR("Ack message was null!\n");
    return -1;
  }

  spin_lock_bh(&create_ack_lock);
  if(data->record_id == ACK_MESSAGE &&
      data->counter == ack_record.counter)
  {

    resetAckRecord();
    // Let the user process wake up since the ack was 
    //   received
    up(&ack_semaphore);

  }
  ack_record.counter = counter;
  spin_unlock_bh(&create_ack_lock);
  return 0;

}

//************************************************************************
/**
 *  Process event packet received
 */
void processEventPacket(EventMessage* data, unsigned int len)
{

  if(data == NULL)
  {
    ERROR("Event message was null!\n");
    return;
  }

  addBuffer(data->data, len);
}

//************************************************************************
/**
 *  Receive packets on the new protocol
 */
int cse536_receive(struct sk_buff* skb)
{

  unsigned char* transport_data = NULL;
  uint32_t record_id = UNKNOWN_MESSAGE;

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

  DEBUG("Received an IP packet! skb->data_len[%d]\n",
      skb->data_len);
  DEBUG("skb->end[%d]\n",
      skb->end);
  DEBUG("skb->len-sizeof(struct iphdr)[%zu]\n",
      (size_t)(skb->len-sizeof(struct iphdr)));
  DEBUG("skb->len[%d]\n",
      skb->len);
  DEBUG("skb->tail[%d]\n",
      skb->tail);
  DEBUG("skb->mac_header[%d]\n",
      skb->mac_header);
  DEBUG("skb->head[%zu]\n",
      (size_t)skb->head);
  DEBUG("transport_data[%zu]\n",
      (size_t)transport_data);
  DEBUG("data: %s\n",
      transport_data);

  record_id = *(uint32_t*)(transport_data);
  if(record_id == ACK_MESSAGE)
  {
    processAckPacket((AckMessage*)transport_data);
  }
  else if(record_id == EVENT_MESSAGE)
  {
    processEventPacket((EventMessage*)transport_data,
        skb->len);
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

  //spin_lock_bh(&rec_lock);
  down(&receive_semaphore);

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
  up(&receive_semaphore);
  //spin_unlock_bh(&rec_lock);
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

MessageType getMessageType(const char* buff, size_t count)
{

  unsigned int message_type = 
    *((unsigned int*)buff);

  if(count < 4)
  {
    return UNKNOWN_MESSAGE;
  }

  switch(message_type)
  {
    case ACK_MESSAGE:
      DEBUG("Found ACK message\n");
      break;
    case EVENT_MESSAGE:
      DEBUG("Found EVENT message\n");
      break;
    default:
      ERROR("Cannot find message type for packet!\n");
      return UNKNOWN_MESSAGE;
  }
  return message_type;
}

//************************************************************************
/**
 *   Wait for ACK packet from receiver or timeout
 */
static void waitForACK()
{

  long jiffies_timeout = msecs_to_jiffies(MSECONDS_TO_WAIT);

  // Wait till TCP thread releases us on ACK
  //    (or timeout is exceeded)
  int result = down_timeout(&ack_semaphore, jiffies_timeout);

  if(result == -ETIME)
  {
    spin_lock_bh(&create_ack_lock);
    DEBUG("Ack never received!!! For counter: %d\n",
        ack_record.counter);
    resetAckRecord();
    spin_unlock_bh(&create_ack_lock);
  }
}

//************************************************************************
static ssize_t cse536_write(struct file *file, const char *buf,
    size_t count, loff_t * ppos)
{

  __be32* daddr_ptr = NULL;
  const unsigned char* data_buff = NULL;
  __be32 daddr = 0;
  __be32 saddr = getSourceAddr();
  size_t count_to_send = 0;
  unsigned char* temp_buf = NULL;

  MessageType message_type = UNKNOWN_MESSAGE;

  if(buf == NULL)
  {

    ERROR("buffer to send was null!!\n");
    return 0;
  }
  if(count > MAX_BUFFER_SIZE)
  {
    ERROR("Received a message size, %zu, "
        "that is longer than the "
        "max allowed by this protocol: %d\n",
        count, MAX_BUFFER_SIZE);
    return 0;
  }

  // Copy to temp buffer to work on
  temp_buf = 
    (unsigned char*)kmalloc(MAX_BUFFER_SIZE, GFP_ATOMIC);
  memcpy(temp_buf, buf, count);

  message_type = getMessageType(temp_buf, count);
  DEBUG("cse536_write: accepting %zd bytes\n", count);

  daddr_ptr = (__be32*)temp_buf;
  // Move past destination address to get data buffer
  data_buff = (unsigned char*)(&daddr_ptr[1]);
  //  And store destination address
  daddr = *daddr_ptr;

  DEBUG("source addr: 0x%04x\n", saddr);
  DEBUG("destination addr: 0x%04x\n", daddr);
  DEBUG("data_buff:%s\n", data_buff);

  // Count to send = count received - ip size - recordtype size;
  count_to_send = count - sizeof(__be32);

  spin_lock_bh(&create_ack_lock);
  ack_record.rec_address = daddr;
  ack_record.counter = counter;
  spin_unlock_bh(&create_ack_lock);

  sendPacketU32(count_to_send , data_buff, saddr, daddr);
  if(message_type == EVENT_MESSAGE)
  {
    waitForACK();
  }

  kfree(temp_buf);
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

  sema_init(&receive_semaphore, 1);
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
 *  Send out a raw packet using the IP layer.
 *
 *  @param data_size size of @p buffer
 *  @param buffer data to send 
 *  @param saddr ip source address
 *  @param daddr ip dest address
 */

static void sendPacketU32(size_t data_size, 
    const unsigned char* buffer,
    __be32 saddr, __be32 daddr)
{

  const int LENGTH = 1500 + sizeof(struct iphdr) + data_size;
  struct sk_buff* skb = alloc_skb(LENGTH, GFP_ATOMIC);
  struct iphdr* ip_header = NULL;
  unsigned char* transport_data = NULL;
  int err = 0;
  //struct ethhdr* eth = NULL;

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

