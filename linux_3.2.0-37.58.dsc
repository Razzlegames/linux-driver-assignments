-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA1

Format: 1.0
Source: linux
Binary: linux-source-3.2.0, linux-doc, linux-tools-common, linux-headers-3.2.0-37, linux-libc-dev, linux-tools-3.2.0-37, linux-image-3.2.0-37-generic, linux-image-extra-3.2.0-37-generic, linux-headers-3.2.0-37-generic, linux-image-3.2.0-37-generic-dbgsym, linux-image-3.2.0-37-generic-pae, linux-image-extra-3.2.0-37-generic-pae, linux-headers-3.2.0-37-generic-pae, linux-image-3.2.0-37-generic-pae-dbgsym, linux-image-3.2.0-37-highbank, linux-image-extra-3.2.0-37-highbank, linux-headers-3.2.0-37-highbank, linux-image-3.2.0-37-highbank-dbgsym, linux-image-3.2.0-37-omap, linux-image-extra-3.2.0-37-omap, linux-headers-3.2.0-37-omap, linux-image-3.2.0-37-omap-dbgsym, linux-image-3.2.0-37-powerpc64-smp, linux-image-extra-3.2.0-37-powerpc64-smp, linux-headers-3.2.0-37-powerpc64-smp, linux-image-3.2.0-37-powerpc64-smp-dbgsym, linux-image-3.2.0-37-powerpc-smp, linux-image-extra-3.2.0-37-powerpc-smp, linux-headers-3.2.0-37-powerpc-smp, linux-image-3.2.0-37-powerpc-smp-dbgsym,
 linux-image-3.2.0-37-virtual, linux-image-extra-3.2.0-37-virtual, linux-headers-3.2.0-37-virtual, linux-image-3.2.0-37-virtual-dbgsym, kernel-image-3.2.0-37-generic-di, nic-modules-3.2.0-37-generic-di, nic-shared-modules-3.2.0-37-generic-di, serial-modules-3.2.0-37-generic-di, ppp-modules-3.2.0-37-generic-di, pata-modules-3.2.0-37-generic-di, firewire-core-modules-3.2.0-37-generic-di, scsi-modules-3.2.0-37-generic-di, plip-modules-3.2.0-37-generic-di, floppy-modules-3.2.0-37-generic-di, fat-modules-3.2.0-37-generic-di, nfs-modules-3.2.0-37-generic-di, md-modules-3.2.0-37-generic-di, multipath-modules-3.2.0-37-generic-di, usb-modules-3.2.0-37-generic-di, pcmcia-storage-modules-3.2.0-37-generic-di, fb-modules-3.2.0-37-generic-di, input-modules-3.2.0-37-generic-di, mouse-modules-3.2.0-37-generic-di, irda-modules-3.2.0-37-generic-di, parport-modules-3.2.0-37-generic-di, nic-pcmcia-modules-3.2.0-37-generic-di, pcmcia-modules-3.2.0-37-generic-di,
 nic-usb-modules-3.2.0-37-generic-di, sata-modules-3.2.0-37-generic-di, crypto-modules-3.2.0-37-generic-di, squashfs-modules-3.2.0-37-generic-di, speakup-modules-3.2.0-37-generic-di, virtio-modules-3.2.0-37-generic-di, fs-core-modules-3.2.0-37-generic-di, fs-secondary-modules-3.2.0-37-generic-di, storage-core-modules-3.2.0-37-generic-di, block-modules-3.2.0-37-generic-di, message-modules-3.2.0-37-generic-di, vlan-modules-3.2.0-37-generic-di, ipmi-modules-3.2.0-37-generic-di, kernel-image-3.2.0-37-virtual-di, nic-modules-3.2.0-37-virtual-di, nic-shared-modules-3.2.0-37-virtual-di, scsi-modules-3.2.0-37-virtual-di, floppy-modules-3.2.0-37-virtual-di, fat-modules-3.2.0-37-virtual-di, md-modules-3.2.0-37-virtual-di, multipath-modules-3.2.0-37-virtual-di, fb-modules-3.2.0-37-virtual-di, mouse-modules-3.2.0-37-virtual-di, irda-modules-3.2.0-37-virtual-di, parport-modules-3.2.0-37-virtual-di, crypto-modules-3.2.0-37-virtual-di, squashfs-modules-3.2.0-37-virtual-di,
 virtio-modules-3.2.0-37-virtual-di, fs-core-modules-3.2.0-37-virtual-di, fs-secondary-modules-3.2.0-37-virtual-di, storage-core-modules-3.2.0-37-virtual-di, block-modules-3.2.0-37-virtual-di, message-modules-3.2.0-37-virtual-di,
 vlan-modules-3.2.0-37-virtual-di
Architecture: all i386 amd64 powerpc ppc64 armel armhf
Version: 3.2.0-37.58
Maintainer: Ubuntu Kernel Team <kernel-team@lists.ubuntu.com>
Standards-Version: 3.8.4.0
Vcs-Git: http://kernel.ubuntu.com/git-repos/ubuntu/ubuntu-precise.git
Build-Depends: debhelper (>= 5), cpio, module-init-tools, kernel-wedge (>= 2.24ubuntu1), makedumpfile [amd64 i386], device-tree-compiler [powerpc], libelf-dev, libnewt-dev, binutils-dev, rsync, libdw-dev, dpkg (>= 1.16.0~ubuntu4), util-linux
Build-Depends-Indep: xmlto, docbook-utils, ghostscript, transfig, bzip2, sharutils, asciidoc
Build-Conflicts: findutils (= 4.4.1-1ubuntu1)
Package-List: 
 block-modules-3.2.0-37-generic-di udeb debian-installer standard
 block-modules-3.2.0-37-virtual-di udeb debian-installer standard
 crypto-modules-3.2.0-37-generic-di udeb debian-installer extra
 crypto-modules-3.2.0-37-virtual-di udeb debian-installer extra
 fat-modules-3.2.0-37-generic-di udeb debian-installer standard
 fat-modules-3.2.0-37-virtual-di udeb debian-installer standard
 fb-modules-3.2.0-37-generic-di udeb debian-installer standard
 fb-modules-3.2.0-37-virtual-di udeb debian-installer standard
 firewire-core-modules-3.2.0-37-generic-di udeb debian-installer standard
 floppy-modules-3.2.0-37-generic-di udeb debian-installer standard
 floppy-modules-3.2.0-37-virtual-di udeb debian-installer standard
 fs-core-modules-3.2.0-37-generic-di udeb debian-installer standard
 fs-core-modules-3.2.0-37-virtual-di udeb debian-installer standard
 fs-secondary-modules-3.2.0-37-generic-di udeb debian-installer standard
 fs-secondary-modules-3.2.0-37-virtual-di udeb debian-installer standard
 input-modules-3.2.0-37-generic-di udeb debian-installer standard
 ipmi-modules-3.2.0-37-generic-di udeb debian-installer standard
 irda-modules-3.2.0-37-generic-di udeb debian-installer standard
 irda-modules-3.2.0-37-virtual-di udeb debian-installer standard
 kernel-image-3.2.0-37-generic-di udeb debian-installer extra
 kernel-image-3.2.0-37-virtual-di udeb debian-installer extra
 linux-doc deb doc optional
 linux-headers-3.2.0-37 deb devel optional
 linux-headers-3.2.0-37-generic deb devel optional
 linux-headers-3.2.0-37-generic-pae deb devel optional
 linux-headers-3.2.0-37-highbank deb devel optional
 linux-headers-3.2.0-37-omap deb devel optional
 linux-headers-3.2.0-37-powerpc-smp deb devel optional
 linux-headers-3.2.0-37-powerpc64-smp deb devel optional
 linux-headers-3.2.0-37-virtual deb devel optional
 linux-image-3.2.0-37-generic deb kernel optional
 linux-image-3.2.0-37-generic-dbgsym deb devel optional
 linux-image-3.2.0-37-generic-pae deb kernel optional
 linux-image-3.2.0-37-generic-pae-dbgsym deb devel optional
 linux-image-3.2.0-37-highbank deb kernel optional
 linux-image-3.2.0-37-highbank-dbgsym deb devel optional
 linux-image-3.2.0-37-omap deb kernel optional
 linux-image-3.2.0-37-omap-dbgsym deb devel optional
 linux-image-3.2.0-37-powerpc-smp deb kernel optional
 linux-image-3.2.0-37-powerpc-smp-dbgsym deb devel optional
 linux-image-3.2.0-37-powerpc64-smp deb kernel optional
 linux-image-3.2.0-37-powerpc64-smp-dbgsym deb devel optional
 linux-image-3.2.0-37-virtual deb kernel optional
 linux-image-3.2.0-37-virtual-dbgsym deb devel optional
 linux-image-extra-3.2.0-37-generic deb kernel optional
 linux-image-extra-3.2.0-37-generic-pae deb kernel optional
 linux-image-extra-3.2.0-37-highbank deb kernel optional
 linux-image-extra-3.2.0-37-omap deb kernel optional
 linux-image-extra-3.2.0-37-powerpc-smp deb kernel optional
 linux-image-extra-3.2.0-37-powerpc64-smp deb kernel optional
 linux-image-extra-3.2.0-37-virtual deb kernel optional
 linux-libc-dev deb devel optional
 linux-source-3.2.0 deb devel optional
 linux-tools-3.2.0-37 deb devel optional
 linux-tools-common deb kernel optional
 md-modules-3.2.0-37-generic-di udeb debian-installer standard
 md-modules-3.2.0-37-virtual-di udeb debian-installer standard
 message-modules-3.2.0-37-generic-di udeb debian-installer standard
 message-modules-3.2.0-37-virtual-di udeb debian-installer standard
 mouse-modules-3.2.0-37-generic-di udeb debian-installer extra
 mouse-modules-3.2.0-37-virtual-di udeb debian-installer extra
 multipath-modules-3.2.0-37-generic-di udeb debian-installer extra
 multipath-modules-3.2.0-37-virtual-di udeb debian-installer extra
 nfs-modules-3.2.0-37-generic-di udeb debian-installer standard
 nic-modules-3.2.0-37-generic-di udeb debian-installer standard
 nic-modules-3.2.0-37-virtual-di udeb debian-installer standard
 nic-pcmcia-modules-3.2.0-37-generic-di udeb debian-installer standard
 nic-shared-modules-3.2.0-37-generic-di udeb debian-installer standard
 nic-shared-modules-3.2.0-37-virtual-di udeb debian-installer standard
 nic-usb-modules-3.2.0-37-generic-di udeb debian-installer standard
 parport-modules-3.2.0-37-generic-di udeb debian-installer standard
 parport-modules-3.2.0-37-virtual-di udeb debian-installer standard
 pata-modules-3.2.0-37-generic-di udeb debian-installer standard
 pcmcia-modules-3.2.0-37-generic-di udeb debian-installer standard
 pcmcia-storage-modules-3.2.0-37-generic-di udeb debian-installer standard
 plip-modules-3.2.0-37-generic-di udeb debian-installer standard
 ppp-modules-3.2.0-37-generic-di udeb debian-installer standard
 sata-modules-3.2.0-37-generic-di udeb debian-installer standard
 scsi-modules-3.2.0-37-generic-di udeb debian-installer standard
 scsi-modules-3.2.0-37-virtual-di udeb debian-installer standard
 serial-modules-3.2.0-37-generic-di udeb debian-installer standard
 speakup-modules-3.2.0-37-generic-di udeb debian-installer extra
 squashfs-modules-3.2.0-37-generic-di udeb debian-installer extra
 squashfs-modules-3.2.0-37-virtual-di udeb debian-installer extra
 storage-core-modules-3.2.0-37-generic-di udeb debian-installer standard
 storage-core-modules-3.2.0-37-virtual-di udeb debian-installer standard
 usb-modules-3.2.0-37-generic-di udeb debian-installer standard
 virtio-modules-3.2.0-37-generic-di udeb debian-installer standard
 virtio-modules-3.2.0-37-virtual-di udeb debian-installer standard
 vlan-modules-3.2.0-37-generic-di udeb debian-installer extra
 vlan-modules-3.2.0-37-virtual-di udeb debian-installer extra
Checksums-Sha1: 
 591f0741ea1b21fa35967cb74170be9f5d3e62d9 98621205 linux_3.2.0.orig.tar.gz
 af25ba467ee5a2f446728e34c21848361aeaec57 3542229 linux_3.2.0-37.58.diff.gz
Checksums-Sha256: 
 ac093c899c5f967fc71816fbd18ca3f73673e64d2a99253bcbc2570c91527f7e 98621205 linux_3.2.0.orig.tar.gz
 79544caeca7207a7212ba2fb00bf536a712ddfc8b476b3956cebcef115121c0b 3542229 linux_3.2.0-37.58.diff.gz
Files: 
 bed3167d6e8c44f463d4f42870598ee2 98621205 linux_3.2.0.orig.tar.gz
 b60e9fa0139b323e9eb57dd716412512 3542229 linux_3.2.0-37.58.diff.gz

-----BEGIN PGP SIGNATURE-----
Version: GnuPG v1.4.12 (GNU/Linux)

iQIcBAEBAgAGBQJRAU7zAAoJENt0rrj9ziT86oQQAIZ84jFHo+rOKawLBK3K+SMW
DuPGXZs+fV08KL7ZvdtLw7WqgyT49q30KVpdHCECu9FS0NfpOoGunng6Hxq9+wtA
pD5+sYKVtK+saHSlPuMb7DGb4OFdPPlH6EM2+CYeK01aIKUKHArtNqLbvrB3xS39
3HEs1vTeBv63aSbIV2i2gmELbCbUQnWl5OKmc+nyP1fFJwEf8Q/ZJORg6zCwNAD3
cl7NAEqeeUIaahZ7Vyoi4wK/lv08Rvrujw77G0uNM7majLdK34YtbwFYiM0FQxik
MwVGw8PkUfZhfWzNKoSBRP3hY9/fHSN4to7Pql08Kq2elP6jVevZEzJnWIPK3ONd
Wz8YfuiV4YthguwUhvFAabgoCCgbJJYp4eSdlnwaFdUvENXNBeFVn3fyI/qDQL9I
Qi1UsEZyeQPrKrm27y7lOW4SZ+uP98S4WuT4hp6EFShUEhWapqMgIQ/+On+IUVF5
UO+joYPFAdQfyG7tOGce/aiTaFXqiq9K/fpg644C79TuFJUR5LlpMyu/E2jMCQI/
nR/TLFwX5KohHfiq1U8Dd8rWCxo3idxPSqimJBoOunfMhN0qYWiNrp/CuJPeLPvu
vQS8tZSJeAyD1tpOiOmTtwiJQuCxPzLk230kZi5e6Bhesg4qXC7qTgf3KBoM0204
L/VKoBl4qIw2wMlagpVH
=cFum
-----END PGP SIGNATURE-----
