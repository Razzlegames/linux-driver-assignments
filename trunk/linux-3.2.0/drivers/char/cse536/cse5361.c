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

/// Attempt to use an unreserved IP protocol number
#define IPPROTO_CSE536  253
#define CSE536_MAJOR 234

static int debug_enable = 0;
module_param(debug_enable, int, 0);
MODULE_PARM_DESC(debug_enable, "Enable module debug mode.");
struct file_operations cse536_fops;

#define ERROR(s, ...) \
  printk(KERN_ERR "%s:%d ERROR: " s, __FILE__, __LINE__, ##__VA_ARGS__); \

static void cse536_err(struct sk_buff *skb, u32 info);

static int cse536_open(struct inode *inode, struct file *file)
{
  printk("cse536_open: successful\n");
  return 0;
}

static int cse536_release(struct inode *inode, struct file *file)
{
  printk("cse536_release: successful\n");
  return 0;
}

static ssize_t cse536_read(struct file *file, char *buf, size_t count,
    loff_t *ptr)
{
  size_t retCount;
  retCount = sprintf(buf, "cse536");
  printk("cse536_read: returning %zu bytes\n", retCount);
  return retCount;
}

static ssize_t cse536_write(struct file *file, const char *buf,
    size_t count, loff_t * ppos)
{
  printk("cse536_write: accepting zero bytes\n");
  return 0;
}

static long cse536_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
  printk("cse536_ioctl: cmd=%d, arg=%ld\n", cmd, arg);
  return 0;
}

static const struct net_protocol cse536_protocol = {
	.handler	=	xfrm4_rcv,
	.err_handler	=	cse536_err,
	.no_policy	=	1,
	.netns_ok	=	1,
};

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

	if (inet_add_protocol(&cse536_protocol, IPPROTO_CSE536) < 0) 
  {
		ERROR("Could not register cse536_protocol!");
		return -EAGAIN;
	}
	return 0;

  printk("cse536: registered module successfully!\n");
  /* Init processing here... */
  return 0;

}

static void __exit cse536_exit(void)
{
  unregister_chrdev(CSE536_MAJOR, "cse5361"); 
  printk("cse536 module Exit\n");
}

struct file_operations cse536_fops = {
owner: THIS_MODULE,
       read: cse536_read,
       write: cse536_write,
       unlocked_ioctl: cse536_ioctl,
       open: cse536_open,
       release: cse536_release,
};

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

module_init(cse536_init);
module_exit(cse536_exit);

MODULE_AUTHOR("Kyle Luce");
MODULE_DESCRIPTION("cse536 Module");
MODULE_LICENSE("GPL");

