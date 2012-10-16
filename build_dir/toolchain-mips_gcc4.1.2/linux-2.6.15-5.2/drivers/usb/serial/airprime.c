/*
 * AirPrime CDMA Wireless Serial USB driver
 *
 * Copyright (C) 2005 Greg Kroah-Hartman <gregkh@suse.de>
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License version
 *	2 as published by the Free Software Foundation.
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/tty.h>
#include <linux/module.h>
#include <linux/usb.h>
#include "usb-serial.h"

//#define DRIVECAM_MOD

static int debug;
static int nmea = 1;
static int truinstall;

/* per port private data */
#ifdef DRIVECAM_MOD
/* our philips usb host controller driver has trouble with anything more than this */
#  define N_IN_URB	1
#  define N_OUT_URB	1
#  define IN_BUFLEN	64
#else
#  define N_IN_URB	4
#  define N_OUT_URB	4
#  define IN_BUFLEN	4096
#endif

enum devicetype {
	DEVICE_MODEM =		0,
	DEVICE_INSTALLER =	1,
};

#define DEVICE_INSTALLER_EJECT 18

/* Used in interface blacklisting */
struct sierra_iface_info {
	const u32 infolen;	/* number of interface numbers on blacklist */
	const u8  *ifaceinfo;	/* pointer to the array holding the numbers */
};

/* static device type specific data */
struct sierra_device_static_info {
	const enum devicetype		dev_type;
	const struct sierra_iface_info	iface_blacklist;
};

/* 'blacklist' of interfaces not served by this driver */
static const u8 direct_ip_non_serial_ifaces[] = { 7, 8, 9, 10, 11 };
static const struct sierra_device_static_info direct_ip_interface_blacklist = {
	.dev_type = DEVICE_MODEM,
	.iface_blacklist = {
		.infolen = ARRAY_SIZE( direct_ip_non_serial_ifaces ),
		.ifaceinfo = direct_ip_non_serial_ifaces,
	},
};



static struct usb_device_id id_table [] = {


        //All cards listed here, and then separately 

        //So Sierra ROM devices eject
        { USB_DEVICE(0x1199, 0x0FFF), .driver_info = DEVICE_INSTALLER_EJECT },

        { USB_DEVICE(0x0af0, 0x7a05) }, //Option Globetrotter HSUPA - NEEDS FIXING - ROM IS SAME ID AS MODEM


        { USB_DEVICE(0x1410, 0x6000) }, //Novatel U760
        { USB_DEVICE(0x1199, 0x0224) }, //Sierra MC5727 #1
        { USB_DEVICE(0x1199, 0x0024) }, //Sierra MC5727 #2
        { USB_DEVICE(0x1199, 0x0028) }, //Sierra MC5728


        //
        //Modems verified working with Back channel below
        //


        { USB_DEVICE(0x1199, 0x0025) }, //Sierra Aircard 598U USB plug
        { USB_DEVICE(0x1199, 0x683c) }, //Sierra MC8790
        { USB_DEVICE(0x1199, 0x6880) }, //Sierra Aircard USB Mercury Connect

        /* Sierra Wireless C888, USB 303, USB 304 */
        { USB_DEVICE_AND_INTERFACE_INFO(0x1199, 0x6890, 0xFF, 0xFF, 0xFF)},

        /* Sierra Wireless Direct IP modems */
        //Including the Sierra USB 305 Lightning
        { USB_DEVICE(0x1199, 0x68A3),
          .driver_info = (kernel_ulong_t)&direct_ip_interface_blacklist 
        },


	{ }, //teminating
};
MODULE_DEVICE_TABLE(usb, id_table);




#define URB_TRANSFER_BUFFER_SIZE        4096
#define NUM_READ_URBS                   4
#define NUM_WRITE_URBS                  4
#define NUM_BULK_EPS                    3
#define MAX_BULK_EPS                    6

/* ******************************************
        CODE TAKEN FROM sierra.c 
******************************************
*/

#define SWIMS_USB_REQUEST_SetPower      0x00
#define SWIMS_USB_REQUEST_SetNmea       0x07
#define SWIMS_USB_REQUEST_SetMode       0x0B
#define SWIMS_USB_REQUEST_TYPE_VSC_SET  0x40
#define SWIMS_SET_MODE_Modem            0x0001

struct sierra_port_private {
	spinlock_t lock;	/* lock the structure */
	int outstanding_urbs;	/* number of out urbs in flight */

	/* Input endpoints and buffers for this port */
	struct urb *in_urbs[N_IN_URB];

	/* Settings for the port */
	int rts_state;	/* Handshaking pins (outputs) */
	int dtr_state;
	int cts_state;	/* Handshaking pins (inputs) */
	int dsr_state;
	int dcd_state;
	int ri_state;
};




int sierra_set_ms_mode(struct usb_device *udev, __u16 eSocMode)
{
        int result;
        dev_dbg(&udev->dev, "%s", "DEVICE MODE SWITCH");
        result = usb_control_msg(udev, usb_sndctrlpipe(udev, 0),
                        SWIMS_USB_REQUEST_SetMode,      /* __u8 request      */
                        SWIMS_USB_REQUEST_TYPE_VSC_SET, /* __u8 request type */
                        eSocMode,                       /* __u16 value       */
                        0x0000,                         /* __u16 index       */
                        NULL,                           /* void *data        */
                        0,                              /* __u16 size        */
                        USB_CTRL_SET_TIMEOUT);          /* int timeout       */
        return result;
}



static int is_blacklisted(const u8 ifnum,
				const struct sierra_iface_info *blacklist)
{
	const u8  *info;
	int i;

	if (blacklist) {
		info = blacklist->ifaceinfo;

		for (i = 0; i < blacklist->infolen; i++) {
			if (info[i] == ifnum)
				return 1;
		}
	}
	return 0;
}

static int sierra_calc_interface(struct usb_serial *serial)
{
	int interface;
	struct usb_interface *p_interface;
	struct usb_host_interface *p_host_interface;
	dev_dbg(&serial->dev->dev, "%s\n", __func__);

	/* Get the interface structure pointer from the serial struct */
	p_interface = serial->interface;

	/* Get a pointer to the host interface structure */
	p_host_interface = p_interface->cur_altsetting;

	/* read the interface descriptor for this active altsetting
	 * to find out the interface number we are on
	*/
	interface = p_host_interface->desc.bInterfaceNumber;

	return interface;
}


//int SierraEject_usb_serial_probe(struct usb_interface *iface, const struct usb_device_id *id)
int SierraEject_usb_serial_probe(struct usb_serial *serial, const struct usb_device_id *id)
{
        int result;
        struct usb_device *udev;
        u8 ifnum, ifclass; 

        udev = serial->dev;
        //udev = usb_get_dev(interface_to_usbdev(iface));
        //struct usb_interface *iface = serial->interface;

        /* Check if in installer mode */
        if (id->driver_info == DEVICE_INSTALLER_EJECT ){
                dev_dbg(&udev->dev, "%s", "FOUND DEVICE INSTALLER\n");
                result = sierra_set_ms_mode(udev, SWIMS_SET_MODE_Modem);
                /*We do not want to bind to the device when in installer mode*/
                return -EIO;
        }

        ifnum = sierra_calc_interface(serial);
        if (serial->interface->num_altsetting == 2) {
        //if (iface->num_altsetting == 2) {

            //printk("DEBUG: selecting alternate setting for %d\n",ifnum);
            dev_dbg(&udev->dev, "Selecting alt setting for interface %d\n",
                ifnum);
            /* We know the alternate setting is 1 for the MC8785 */
            usb_set_interface(udev, ifnum, 1);
        }

        //return usb_serial_probe(iface, id);
        return 0;
}



static int sierra_calc_num_ports(struct usb_serial *serial)
{
	int num_ports = 0;
	u8 ifnum, numendpoints;
	
	dev_dbg(&serial->dev->dev, "%s\n", __func__);
	
	ifnum = serial->interface->cur_altsetting->desc.bInterfaceNumber;
	numendpoints = serial->interface->cur_altsetting->desc.bNumEndpoints;
	
	/* Dummy interface present on some SKUs should be ignored */
	if (ifnum == 0x99)
		num_ports = 0;
	else if (numendpoints <= 3)
		num_ports = 1;
	else
		num_ports = (numendpoints-1)/2;
	//dev_dbg(&serial->dev->dev, "%s: num_ports=%d numendpoints=%d\n", __func__, num_ports, numendpoints);
	//printk("%s: num_ports=%d numendpoints=%d\n",  __func__, num_ports, numendpoints);
	return num_ports;
}



/* ******************************************
        END CODE TAKEN FROM sierra.c
*****************************************
*/


static struct usb_driver airprime_driver = {
	.owner =       THIS_MODULE,
	.name =	       "airprime",
	.probe =    usb_serial_probe,
	.disconnect =  usb_serial_disconnect,
	.id_table =	   id_table,
};


static struct usb_serial_driver airprime_device = {
	.driver = {
		.owner =	THIS_MODULE,
		.name =		"airprime",
	},
	.id_table =		    id_table,
    .probe =       SierraEject_usb_serial_probe,
	.num_interrupt_in =	NUM_DONT_CARE,
	.num_bulk_in =		NUM_DONT_CARE,
	.num_bulk_out =		NUM_DONT_CARE,
    .calc_num_ports	   = sierra_calc_num_ports,
	//.num_ports =		1,
};



static int __init airprime_init(void)
{
	int retval;
	retval = usb_serial_register(&airprime_device);
	if (retval)
		goto failed_device_airprime_register;
	retval = usb_register(&airprime_driver);
	if (retval)
		goto failed_driver_register;

	return 0;

failed_driver_register:
	usb_serial_deregister(&airprime_device);
failed_device_airprime_register:
	return retval;
}

static void __exit airprime_exit(void)
{
        usb_deregister(&airprime_driver);
        usb_serial_deregister(&airprime_device);
}


module_init(airprime_init);
module_exit(airprime_exit);
MODULE_LICENSE("GPL");
