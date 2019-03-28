//
//  doit.c
//  powend
//
//  Created by simo on 12/10/2018.
//  Copyright © 2018 simo ghannam. All rights reserved.
//

// THIS IS NOT A JAILBREAK
#include <stdio.h>
#include "code.h"
#include <sys/socket.h>
#include <unistd.h>
#include <mach/mach_traps.h>

extern mach_port_t host_priv;
extern mach_port_t atm_notification_port;

kern_return_t mach_zone_force_gc(host_t host);

void start_jb(void)
{
    
    start_uexploit();
    
    //start_kexploit(host_priv,atm_notification_port);

}
