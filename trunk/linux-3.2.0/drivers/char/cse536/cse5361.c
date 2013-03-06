#include <linux/module.h>
#include <linux/fs.h>
#define CSE536_MAJOR 234
static int debug_enable = 0;
module_param(debug_enable, int, 0);
MODULE_PARM_DESC(debug_enable, "Enable module debug mode.");
struct file_operations cse536_fops;
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
  printk("cse536_read: returning %d bytes\n", retCount);
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
static int __init cse536_init(void)
{
  int ret;
  printk("cse536 module Init - debug mode is %s\n",
      debug_enable ? "enabled" : "disabled");
  ret = register_chrdev(CSE536_MAJOR, "cse5361", &cse536_fops);
  if (ret < 0) {
    printk("Error registering cse536 device\n");
    goto cse536_fail1;
  }
  printk("cse536: registered module successfully!\n");
  /* Init processing here... */
  return 0;
cse536_fail1:
  return ret;
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
module_init(cse536_init);
module_exit(cse536_exit);

MODULE_AUTHOR("Kyle Luce");
MODULE_DESCRIPTION("cse536 Module");
MODULE_LICENSE("GPL");
