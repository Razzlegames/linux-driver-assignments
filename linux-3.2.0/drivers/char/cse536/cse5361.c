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

/// Attempt to use an unreserved IP protocol number
#define IPPROTO_CSE536  253
#define CSE536_MAJOR 234

#define ERROR(s, ...) \
  printk(KERN_ERR "%s:%d ERROR: " s, __FILE__, __LINE__, ##__VA_ARGS__); \

#define DEBUG(s, ...) \
  printk(KERN_DEBUG "%s:%d DEBUG: " s, __FILE__, __LINE__, ##__VA_ARGS__); \

static int debug_enable = 0;
module_param(debug_enable, int, 0);
MODULE_PARM_DESC(debug_enable, "Enable module debug mode.");
struct file_operations cse536_fops;

unsigned char* rec_buffer = NULL;

#define MAX_BUFFER_SIZE 257
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

/// Make sure writes/reads are synced to this list
static DEFINE_MUTEX(receive_list_mutex);
/// The head of the linked list to receive data
static struct receive_list* receive_list_head = NULL;

//static void sendPacket(size_t data_size, const char* buffer,
//    const char* SADDR_STRING,
//    const char* DADDR_STRING);

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

static struct receive_list* last_read = NULL;
//static void clearOldBuffers(void);

DEFINE_SPINLOCK(rec_lock);

//************************************************************************
struct receive_list* allocateBuffer(unsigned char* buffer, 
    size_t size)
{

    struct receive_list* r =  (struct receive_list*)kmalloc(
        sizeof(struct receive_list), GFP_KERNEL);
    if(r == NULL)
    {
      ERROR("Could not allocate space for receive list!\n");
      return NULL;
    }
    if(size > MAX_BUFFER_SIZE)
    {
      size = MAX_BUFFER_SIZE;
      DEBUG("Adjusted size to: %d\n", size);
    }
    memcpy(r->buffer, buffer, size);
    r->size = size;
    return r;
}

////************************************************************************
//static void clearOldBuffers(void)
//{
//
//    struct receive_list* r =  receive_list_head;
//    struct receive_list* to_clear =  NULL;
//    while(r != last_read)
//    {
//      if(r == NULL)
//      {
//
//        return;
//      }
//      to_clear = r;
//      r = r->next;
//      kfree(to_clear);
//    }
//}


//************************************************************************
struct receive_list* getOldestBufferNotRead(void)
{
  struct receive_list* h = NULL;

  //mutex_lock(&receive_list_mutex);
  spin_lock_bh(&rec_lock);

  h = receive_list_head;
  if(h == NULL)
  {
    //DEBUG("head of list was null!\n");

    spin_unlock_bh(&rec_lock);
    return NULL;
  }

  //receive_list_head = h->next;

  while(h->next != NULL && h != last_read)
  {
    h = h->next;
  }
  if(h->next == NULL)
  {
    spin_unlock_bh(&rec_lock);
    return NULL;
  }

  last_read = h->next;
  DEBUG("Returning found buffer!\n");

  spin_unlock_bh(&rec_lock);
  return h->next;

  //mutex_unlock(&receive_list_mutex);

  //return h;
}

//************************************************************************
/**
 *  Delete all linked lists of received packets
 */
static void deleteBuffers(void)
{
  spin_lock_bh(&rec_lock);

  struct receive_list* to_delete = NULL;
  struct receive_list* h = receive_list_head;
  int i = 0;
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
  spin_unlock_bh(&rec_lock);
}

//************************************************************************
void addBuffer(unsigned char* buffer, size_t size)
{
  struct receive_list* list_current = NULL;
  DEBUG("Adding packet[%zu]\n", size);

  spin_lock_bh(&rec_lock);
  //mutex_lock(&receive_list_mutex);

  list_current = receive_list_head;
  if(list_current == NULL)
  {
    DEBUG("Allocated buffer on head\n");
    receive_list_head = allocateBuffer(buffer, size);

    spin_unlock_bh(&rec_lock);
    return;
  }

  while(list_current->next != NULL)
  {
    list_current = list_current->next;
  }
  DEBUG("Allocated buffer on tail\n");
  list_current->next = allocateBuffer(buffer, size);

  spin_unlock_bh(&rec_lock);
  //mutex_unlock(&receive_list_mutex);

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
 *  Receive packets on the new protocol
 */
int cse536_receive(struct sk_buff* skb)
{

  unsigned char* transport_data = NULL;
  unsigned char* cur = NULL;
  unsigned char* end = NULL;
  //int i = 0;

  if(skb == NULL)
  {
    ERROR("packet received was NULL!\n");
    return -1;
  }

  transport_data = skb_transport_header(skb);
  DEBUG("Received a packet! skb->data_len[%d]\n",
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

  //  DEBUG("Packet in hex: ");
  //  cur = transport_data;
  //  end = transport_data + skb->len;
  //  while(cur < end)
  //  {
  //
  //    printk("%02x", *cur);
  //    cur++;
  //  }
  //  printk("\n");

  addBuffer(transport_data, skb->len);

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

  //DEBUG("entered read! count: %zu\n", count);

  read_entry = getOldestBufferNotRead();
  if(read_entry == NULL)
  {
    return 0;
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

//************************************************************************
static ssize_t cse536_write(struct file *file, const char *buf,
    size_t count, loff_t * ppos)
{

  //const char* SADDR_STRING = "192.168.2.8";
  __be32* daddr_ptr = NULL;
  const unsigned char* data_buff = NULL;
  __be32 daddr = 0;
  __be32 saddr = getSourceAddr();
  size_t count_to_send = 0;

  if(buf == NULL)
  {

    ERROR("buffer to send was null!!\n");
    return 0;
  }
  else if(*buf == IP_RECORD)
  {

    DEBUG("cse536_write: accepting %zd bytes\n", count);
    // Move past record type byte
    daddr_ptr = (__be32*)&buf[1];
    data_buff = (unsigned char*)(&daddr_ptr[1]);
    daddr = *daddr_ptr;

    DEBUG("source addr: 0x%04x\n", saddr);
    DEBUG("destination addr: 0x%04x\n", daddr);
    DEBUG("data_buff:%s\n", data_buff);

    // Count to send = count received - ip size - recordtype size;
    count_to_send = count - sizeof(__be32) - sizeof(uint8_t);

    sendPacketU32(count_to_send , data_buff, saddr, daddr);
    return count;
  }
  return 0;
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

  //	if (xfrm_register_type(&esp_type, AF_INET) < 0) {
  //		printk(KERN_INFO "ip esp init: can't add xfrm type\n");
  //		return -EAGAIN;
  //	}

  ret = inet_add_protocol(&cse536_protocol, IPPROTO_CSE536);
  if(ret < 0)
  {
    ERROR("Could not register cse536_protocol!");
    inet_del_protocol(&cse536_protocol, IPPROTO_CSE536);
    return ret;
  }

  printk("cse536: registered module successfully!\n");
  /* Init processing here... */
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

  struct net *net = dev_net(skb->dev);
  const struct iphdr *iph = (const struct iphdr *)skb->data;
  struct ip_esp_hdr *esph = 
    (struct ip_esp_hdr *)(skb->data+(iph->ihl<<2));
  struct xfrm_state *x;

  if (icmp_hdr(skb)->type != ICMP_DEST_UNREACH ||
      icmp_hdr(skb)->code != ICMP_FRAG_NEEDED)
      return;

  x = xfrm_state_lookup(net, skb->mark, (const xfrm_address_t *)&iph->daddr,
      esph->spi, IPPROTO_ESP, AF_INET);
  if (!x)
      return;
  NETDEBUG(KERN_DEBUG "pmtu discovery on SA ESP/%08x/%08x\n",
      ntohl(esph->spi), ntohl(iph->daddr));
  xfrm_state_put(x);
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

