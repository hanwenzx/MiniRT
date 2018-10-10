/**********************************************************************
* file:  sr_router.c
*
* Description:
*
* This file contains all the functions that interact directly
* with the routing table, as well as the main entry method
* for routing.
*
**********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"


/*---------------------------------------------------------------------
* Method: sr_init(void)
* Scope:  Global
*
* Initialize the routing subsystem
*
*---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
/* REQUIRES */
  assert(sr);

/* Initialize cache and cache cleanup thread */
  sr_arpcache_init(&(sr->cache));

  pthread_attr_init(&(sr->attr));
  pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
  pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
  pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
  pthread_t thread;

  pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

/* Add initialization code here! */

} 
/* -- sr_init -- */

/*---------------------------------------------------------------------
* Method: sr_handlepacket(uint8_t* p,char* interface)
* Scope:  Global
*
* This method is called each time the router receives a packet on the
* interface.  The packet buffer, the packet length and the receiving
* interface are passed in as parameters. The packet is complete with
* ethernet headers.
*
* Note: Both the packet buffer and the character's memory are handled
* by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
* packet instead if you intend to keep it around beyond the scope of
* the method call.
*
*---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
  uint8_t * packet/* lent */,
  unsigned int len,
  char* interface/* lent */){
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);
  /* fill in code here */
  struct sr_if* if_ = sr_get_interface(sr, interface);
  if (!if_) return;
  sr_ethernet_hdr_t * eth_hdr = (sr_ethernet_hdr_t *)packet;
  if (ethertype(packet) == ethertype_arp)
    goto ARP;
  else if (ethertype(packet) == ethertype_ip)
    goto IP;

ARP:  
  ;sr_arp_hdr_t * arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  /* IP mismatch */
  if (if_->ip != arp_hdr->ar_tip){
    return;
  }

  /* reply ARP request */
  if (ntohs(arp_hdr->ar_op) == arp_op_request){
    memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
    memcpy(eth_hdr->ether_shost, if_->addr, ETHER_ADDR_LEN);
    arp_hdr->ar_op = htons(arp_op_reply);
    arp_hdr->ar_tip = arp_hdr->ar_sip;
    arp_hdr->ar_sip = if_->ip;
    memcpy(arp_hdr->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
    memcpy(arp_hdr->ar_sha, if_->addr, ETHER_ADDR_LEN);
    sr_send_packet(sr, packet, len, interface);

  }
  /* process ARP reply */
  else if (ntohs(arp_hdr->ar_op) == arp_op_reply){
    struct sr_arpreq* req = sr_arpcache_insert(&(sr->cache), arp_hdr->ar_sha, arp_hdr->ar_sip);
    if (!req) {
      return;
    }
    struct sr_packet* packets = req->packets;
    
    /* send cached packets */
    while (packets){
      sr_ethernet_hdr_t* rep_eth_hdr = (sr_ethernet_hdr_t*)packets->buf;
      memcpy(rep_eth_hdr->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
      memcpy(rep_eth_hdr->ether_shost, if_->addr, ETHER_ADDR_LEN);
      sr_send_packet(sr, packets->buf, packets->len, packets->iface);
      packets = packets->next;
    }
  }
  return;

IP:
  ;sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
  if (ip_hdr->ip_v != 4){
    return;
  }
  /* IP header checksum */
  uint16_t ip_hdr_sum = ip_hdr->ip_sum;
  ip_hdr->ip_sum = 0;
  
  /* checksum fails */
  if (cksum(ip_hdr, sizeof(sr_ip_hdr_t)) != ip_hdr_sum){
    return;
  }
  else ip_hdr->ip_sum = ip_hdr_sum;

  /* IP to router */
  if (ip_hdr->ip_dst == if_->ip){

    /* handle non-ICMP packet */
    if (ip_hdr->ip_p != ip_protocol_icmp){
      sr_send_icmp(sr, packet, interface, 3, 3);
      return;
    }

    /* handle ICMP packet */
    else {
      sr_icmp_t11_hdr_t * icmp_hdr = (sr_icmp_t11_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
      if (icmp_hdr->icmp_type != 8) {
        return;
      }
      sr_ping_back(sr, packet, len, interface);
      return;
    }
  }

  /* forward */
  else {
    /* check TTL */
    if (ip_hdr->ip_ttl <= 1){
      sr_send_icmp(sr, packet, interface, 11, 0);
      return;
    }
    /* Look up next-hop address by doing a LPM on the routing 
    table using the packet’sdestination address. If it does 
    not exist, send ICMP host unreachable (type 3, code 0).*/
    else {
      uint32_t lpm = 0;
      struct sr_rt * current_rt = sr->routing_table; 
      struct sr_rt * lpm_rt = NULL;
      while (current_rt){
        uint32_t mask_0 = ntohs(current_rt->dest.s_addr) & ntohs(current_rt->mask.s_addr);
        uint32_t mask_1 = ntohs(current_rt->mask.s_addr) & ntohs(ip_hdr->ip_dst);
        if (mask_1 == mask_0){
          if (mask_0 > lpm){
            lpm = mask_1 & mask_0;
            lpm_rt = current_rt;
          }
        }
        current_rt = current_rt->next;
      }
      
      /* network unreachable */
      if (lpm == 0){
        sr_send_icmp(sr, packet, interface, 3, 0);
        return;
      }

      /* LPM found, update IP */
      ip_hdr->ip_ttl--;
      ip_hdr->ip_sum = 0;
      ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

      /* ARP lookup */
      struct sr_if* lpm_if = sr_get_interface(sr, lpm_rt->interface);
      struct sr_arpentry* arp_entry = sr_arpcache_lookup(&sr->cache, lpm_if->ip);
      if (arp_entry){
        memcpy(eth_hdr->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
        memcpy(eth_hdr->ether_shost, lpm_if->addr, ETHER_ADDR_LEN);
        sr_send_packet(sr, packet, len, lpm_rt->interface);
      }

      /* create ARP request */
      else {
        struct sr_arpreq* req = sr_arpcache_queuereq(&sr->cache, lpm_rt->gw.s_addr, packet, len, lpm_if->name);
        handle_arpreq(req, sr);
      } 
    }
    return;
  }

}
/* end sr_ForwardPacket */

void sr_ping_back(struct sr_instance* sr, uint8_t* packet, uint8_t len, const char* interface){
  struct sr_if* if_ = sr_get_interface(sr, interface);
  sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t *)packet;
  sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
  sr_icmp_t11_hdr_t* icmp_hdr = (sr_icmp_t11_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  icmp_hdr->icmp_type = 0;
  icmp_hdr->icmp_sum = 0;
  icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_t11_hdr_t));

  ip_hdr->ip_ttl = INIT_TTL;
  ip_hdr->ip_dst = ip_hdr->ip_src;
  ip_hdr->ip_src = if_->ip;
  ip_hdr->ip_sum = 0;
  ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

  memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
  memcpy(eth_hdr->ether_shost, if_->addr, ETHER_ADDR_LEN);
  sr_send_packet(sr, packet, len, interface);
}

void sr_send_icmp(struct sr_instance* sr, uint8_t* packet, const char* interface, uint8_t icmp_type, uint8_t icmp_code){
  struct sr_if* if_ = sr_get_interface(sr, interface);
  sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t *)packet;
  sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
  int reply_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t11_hdr_t);
  uint8_t* reply_pkt = (uint8_t*)malloc(reply_len);

  /* ICMP header */
  sr_icmp_t11_hdr_t* reply_icmp = (sr_icmp_t11_hdr_t *)(reply_pkt 
    + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  memcpy(reply_icmp, packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), sizeof(sr_icmp_t11_hdr_t));
  reply_icmp->icmp_type = icmp_type;
  reply_icmp->icmp_code = icmp_code;
  reply_icmp->icmp_sum = 0;  
  if (icmp_type == 11 || icmp_type == 3){
    memcpy(reply_icmp->data, ip_hdr, ICMP_DATA_SIZE);
  }
  reply_icmp->icmp_sum = cksum(reply_icmp, sizeof(sr_icmp_t11_hdr_t));

  /* ip header */
  struct sr_ip_hdr* reply_ip = (sr_ip_hdr_t *)(reply_pkt + sizeof(sr_ethernet_hdr_t));
  memcpy(reply_ip, ip_hdr, sizeof(sr_ip_hdr_t));
  reply_ip->ip_v = 4;
  reply_ip->ip_p = ip_protocol_icmp;
  reply_ip->ip_ttl = INIT_TTL;
  reply_ip->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t11_hdr_t));
  reply_ip->ip_dst = ip_hdr->ip_src;
  reply_ip->ip_src = if_->ip;
  reply_ip->ip_sum = 0;
  reply_ip->ip_sum = cksum(reply_ip, sizeof(sr_ip_hdr_t));

  /* ethernet header */
  sr_ethernet_hdr_t* reply_eth = (sr_ethernet_hdr_t*)reply_pkt;
  memcpy(reply_eth->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
  memcpy(reply_eth->ether_shost, if_->addr, ETHER_ADDR_LEN);
  reply_eth->ether_type = htons(ethertype_ip);

  sr_send_packet(sr, reply_pkt, reply_len, interface);
  free(reply_pkt);
  return;
}

void handle_arpreq(struct sr_arpreq* req, struct sr_instance* sr){
  time_t now;
  time(&now);
  if (difftime(now, req->sent) <= 1.0) return;
  if (!req) return;
  sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*)req->packets->buf;
  struct sr_if* if_ = sr->if_list;
  
  /* get iface of packet destination MAC */
  while (if_){
    int str_equal = 1;
    int i = 0;
    for (;i < ETHER_ADDR_LEN; i++){
      if (eth_hdr->ether_dhost[i] != if_->addr[i])
        str_equal = 0;
    }
    if (str_equal) break;
    if_ = if_->next;
  }
  char* interface = if_->name;  

  /* ARP timeout */
  if (req->times_sent >= 5){
    sr_send_icmp(sr, req->packets->buf, interface, 3, 1);
    sr_arpreq_destroy(&sr->cache, req);
    return;
  }

  /* get outgoing iface */
  interface = req->packets->iface;
  if_ = sr_get_interface(sr, interface);   

  uint8_t reply_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
  uint8_t* reply_pkt = (uint8_t*)malloc(reply_len);
  
  /* ARP header */
  sr_arp_hdr_t* reply_arp = (sr_arp_hdr_t*)(reply_pkt + sizeof(sr_ethernet_hdr_t));
  reply_arp->ar_hrd = htons(arp_hrd_ethernet);
  reply_arp->ar_pro = htons(ethertype_ip);
  reply_arp->ar_hln = ETHER_ADDR_LEN;
  reply_arp->ar_pln = 4;
  reply_arp->ar_op = htons(arp_op_request);
  memcpy(reply_arp->ar_sha, if_->addr, ETHER_ADDR_LEN);
  reply_arp->ar_sip = if_->ip;
  memset(reply_arp->ar_tha, 0xff, ETHER_ADDR_LEN);
  reply_arp->ar_tip = req->ip;
  
  /* ethernet */
  sr_ethernet_hdr_t* reply_eth = (sr_ethernet_hdr_t*)reply_pkt;
  memset(reply_eth->ether_dhost, 0xff, ETHER_ADDR_LEN);
  memcpy(reply_eth->ether_shost, if_->addr, ETHER_ADDR_LEN);
  reply_eth->ether_type = htons(ethertype_arp);
  sr_send_packet(sr, reply_pkt, reply_len, interface);
  req->sent = now;
  req->times_sent++;
  free(reply_pkt);  
}


