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

static void send(size_t data_size, const char* buffer,
    const char* SADDR_STRING,
    const char* DADDR_STRING);

static void cse536_err(struct sk_buff *skb, u32 info);

//************************************************************************
static const struct net_protocol cse536_protocol = {
	.handler	=	xfrm4_rcv,
	.err_handler	=	cse536_err,
	.no_policy	=	1,
	.netns_ok	=	1,
};

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
  size_t retCount = 0;
  retCount = sprintf(buf, "cse536");
  printk("cse536_read: returning %zu bytes\n", retCount);
  return retCount;
}

//************************************************************************
static ssize_t cse536_write(struct file *file, const char *buf,
    size_t count, loff_t * ppos)
{

  printk("cse536_write: accepting %zd bytes\n", count);
  send(count, buf, "192.168.2.200", "192.168.2.1");
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
 *  Send out a raw packet using the IP layer
 */
static void send(size_t data_size, const char* buffer,
    const char* SADDR_STRING,
    const char* DADDR_STRING)
{

  const int LENGTH = 1500 + sizeof(struct iphdr);
  struct sk_buff* skb = alloc_skb(LENGTH, GFP_ATOMIC);
  struct iphdr* ip_header = NULL;
  unsigned char* transport_data = NULL;
  int err = 0;
  struct ethhdr* eth = NULL;

  __be32 saddr = in_aton(SADDR_STRING);
  __be32 daddr= in_aton(DADDR_STRING);


  DEBUG("Sending data: buffer[%zd] "
      "to: %s, from: %s\n", data_size, DADDR_STRING,
      SADDR_STRING);

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


  //  // Create space in sk_buff for iphdr
  //  DEBUG("Creating space in sk_buff for iphdr\n");
  //  skb_push(skb, sizeof(*ip_header));
  //  skb_reset_network_header(skb);
  //  DEBUG("Done Creating space in sk_buff for iphdr\n");

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

  ip_header->saddr = in_aton(SADDR_STRING);
  ip_header->daddr = in_aton(DADDR_STRING);
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

//***************************************************************
static void cse536_err(struct sk_buff *skb, u32 info)
{

  struct net *net = dev_net(skb->dev);
  const struct iphdr *iph = (const struct iphdr *)skb->data;
  struct ip_esp_hdr *esph = (struct ip_esp_hdr *)(skb->data+(iph->ihl<<2));
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

