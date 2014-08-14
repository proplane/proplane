{{
  PropLANE Main program file.

  Authors: Phork, EvilRob, Russr, and L0st.

  Released under the MIT license, do as you please.
}}
CON
  version = 1     ' major version
  release = 0     ' minor version

  _clkmode = xtal1 + pll16x
  _xinfreq = 5_000_000

' Main Memory buffers for packets.
  ' 1518 mod 16 = 14 + 2 = 1520 for an even AES-256 block size.
  ' Technically, we'll never use more than 1500 in user pkts, and we use a 1400 MTU on the ethernet,
  ' but we pad for unforseen cases (and we have the RAM to spare). 
  inbufferlen = 1520
  outbufferlen = 1520  

  ' pin assignments
  led_eth0_activity = 16
  led_eth1_activity = 17
  led_crypto_key_present = 18
  led_crypto_key_loaded = 19
  led_pulse = 23

  eth0_int = 0
  eth0_scl = 1
  eth0_so = 2
  eth0_si = 3
  eth0_cs = 4
  eth0_rst = 11

  eth1_int = 5
  eth1_scl = 1
  eth1_so = 2
  eth1_si = 3
  eth1_cs = 4
  eth1_rst = 10

  ' Enable encryption.
  enable_crypto_cbc = 0
  enable_crypto_ecb = 1

OBJ
  ' The enc28j60 driver objects.  (roughly 1700 bytes each)
  eth0        : "driver_enc28j60"  ' outside
  eth1        : "driver_enc28j60"  ' inside

  ' The two AES objects.
  aes_enc     : "AES"              ' AES-256 encryptor
  aes_dec     : "AES"              ' AES-256 decryptor

  '' Remove these for production.
  dbg         : "Parallax Serial Terminal"
  num         : "simple_numbers"

DAT
  ' 1520 bytes of memory for each direction.  Encryption happens in place.
  ipkt        byte 0[inbufferlen]
  opkt        byte 0[outbufferlen]
  'enpkt       byte 0[inbufferlen]
  'dcpkt       byte 0[outbufferlen]  
  
  pkt_count0     byte 0
  pkt_count1     byte 0
  pkt_size0      word 0
  pkt_size1      word 0

  ' These are the "op"erational locks that keep the ethernet states clean.
  ' Before reading or writing one must check the lock and spin in place until it's 0.
  ' not great, but it's what we can do on this platform. 
  eth0_op_read_lock byte 0
  eth1_op_read_lock byte 0
  eth0_op_write_lock byte 0
  eth1_op_write_lock byte 0

VAR

  '' Local stacks for the cogs we spawn in this module.
  'long eth0_cogstack[$400]
  'long eth1_cogstack[$400]

  '' Local key variables.
  byte daskey [32]
  long enc_iv[4]
  long dec_iv[4]
    
PUB main | heart, ii ', eth0cog, eth1cog

  ' Serial for debugging.
  dbg.Start(115_200)
  'dbg.Start(9_600)  

  ' AES encryption / decryption cogs.  We do these seperately so we can go async as needed.
  aes_enc.Start
  aes_dec.Start

  ' Load the keys and IVs.
  ResetIV( enc_iv )
  ResetIV( dec_iv )

  ''' TODO: Read Key from Flash Card and use it.
  repeat ii from 0 to 31
    daskey[ii] := $22

  aes_enc.SetKey (128, @daskey)
  aes_dec.SetKey (128, @daskey)


  ' Debug delay only.  (Wait so I can get to the terminal to watch the debug output).
  waitcnt( clkfreq + cnt )
  waitcnt( clkfreq + cnt )
  waitcnt( clkfreq + cnt ) 

  ResetEthControllers

  SetupLEDs
  heart := 0



  ' Get our locks.
  eth0_op_read_lock := LOCKNEW
  eth0_op_write_lock := LOCKNEW
  eth1_op_read_lock := LOCKNEW
  eth1_op_write_lock := LOCKNEW 

  if (eth0_op_read_lock == -1 OR eth0_op_write_lock == -1 OR eth1_op_read_lock == -1 OR eth1_op_write_lock == -1)
    dbg.Str(string("Creation of a lock failed.  Good luck... winging it!", 13))    

  
  dbg.Str(string("Driver Init: eth0:", 13))   
  eth0.start(4, 1, 3, 2, 0, -1)

  dbg.Str(string("Driver Init: eth1:", 13))
  eth1.start(9, 6, 8, 7, 5, -1)

  repeat
    eth0.banksel(eth0#EPKTCNT)
    pkt_count0 := eth0.rd_cntlreg(eth0#EPKTCNT)
    if pkt_count0 > 0
      ' lock recv buffer on outside.
      repeat until not lockset(eth0_op_read_lock)
      'eth0cog := cognew( process_inbound, @eth0_cogstack ) + 1  
      process_inbound
      

    eth1.banksel(eth1#EPKTCNT)  
    pkt_count1 := eth1.rd_cntlreg(eth1#EPKTCNT)
    if pkt_count1 > 0
      ' lock recv buffer on inside.
      repeat until not lockset(eth1_op_read_lock)
      'eth1cog := cognew( process_outbound, @eth1_cogstack ) + 1
      process_outbound
    
    if (heart == $80)     ' 1/64th duty cycle.
      outa[led_pulse] := 1
      heart := 0 
    else
      outa[led_pulse] := 0
      heart++    


PUB process_inbound | pass_unencrypted
  '' This lets the main program get back to the business of being a cogalicious monster.
  pass_unencrypted := 0
  ' copy from eth0 (outside) to eth1 (inside)
  eth0_led_on    
  eth0.get_frame( @ipkt )
  pkt_size0 := eth0.get_rxlen  
  eth0_led_off

  dbg.Str(String("eth0: ("))
  dbg.Dec(pkt_size0)
  dbg.Str(String(") "))

  ' Sanity check.    
  if (pkt_size0 > 1518)
    lockclr(eth0_op_read_lock)
    return      

  'HexDump( String("HexDump of Packet: ") , @ipkt, pkt_size0 )

  if ( test_arp( @ipkt ) )
    pass_unencrypted := 1
  else
    if ( test_ip( @ipkt ) )
      if ( test_udp( @ipkt ) )
        if ( udp_sport( @ipkt ) == udp_dhcp_port_srv ) '' AND udp_dport( @ipkt ) == udp_dhcp_port_cli ) ' pass dhcp to the server from us.
          pass_unencrypted := 1
        if ( udp_sport( @ipkt ) == udp_port_dns )
          pass_unencrypted := 1

  '' DEBUG:
  'if ( test_tcp( @ipkt ) )
  '  dbg.Str(String("IP/TCP "))

  if ( pass_unencrypted == 1 )
    no_crypt_forward_eth1
  else
    ' implicit else, encrypt that sucker.
    decrypt_forward_eth1

  dbg.NewLine

  ' We can process another packet in the buffer now.
  lockclr(eth0_op_read_lock)
  'cogstop(cogid)

PUB no_crypt_forward_eth1
  repeat until not lockset(eth1_op_write_lock)
    
  eth1_led_on    
  eth1.start_frame
  eth1.wr_block( @ipkt, pkt_size0)
  eth1.send_frame
  eth1_led_off
    
  lockclr(eth1_op_write_lock)

PUB decrypt_forward_eth1 | payloadStart, payloadEnd, oldSize, oldProto, ii
  repeat until not lockset(eth1_op_write_lock)

  dbg.Str(String("DECRYPTING "))

  if(test_peeblocker( @ipkt ))

    ' figure out the start and end payload ranges.
    payloadStart := eth_frame_total_size + ip_header_total_length  

    ' This seems to me that it should be right... maybe a bug. -M.  
    'payloadEnd := eth_frame_total_size + (wordflip( word[@ipkt][const_offset_ip_totallen_off/2] ) - ip_header_total_length) 
    payloadEnd := pkt_size0 ' Or it should be...

    'dbg.Str(String("** payloadStart = "))
    'dbg.Dec(payloadStart)
    'dbg.Str(String("** payloadEnd = "))
    'dbg.Dec(payloadEnd)

    ' Reset the encryption IV
    ResetIV( @dec_iv )

    ' attempt decryption in place.
    if (enable_crypto_cbc)
      aes_dec.CBCDecrypt( @ipkt[payloadStart], @ipkt[payloadStart], (payloadEnd - payloadStart)/16, @dec_iv)
    else
      if (enable_crypto_ecb)
        repeat ii from payloadStart to payloadEnd step 16
          aes_dec.ECBDecrypt( @ipkt[ii], @ipkt[ii] )
          

    ' We should be decrypted.  Pull the old protocol number
    oldProto := byte[@ipkt][(payloadEnd - 4)]
    oldSize := word[@ipkt][(payloadEnd - 2)/2]

    'dbg.Str(String("** oldProto = "))
    'dbg.Dec(oldProto)
    'dbg.Str(String("** oldSize = "))
    'dbg.Dec(oldSize)

    ' Reset the protocol
    byte[@ipkt][const_offset_ip_protocol_off] := oldProto ' reset to the original carrier protocol.

    ' Reset the packet size.
    word[@ipkt][const_offset_ip_totallen_off/2] := wordflip( oldSize )

    ' Recompute the IP header checksums.
    word[@ipkt][const_offset_ip_head_csum_off/2] := 0
    word[@ipkt][const_offset_ip_head_csum_off/2] := wordflip( eth1_chksum(@ipkt[eth_frame_total_size], 20) )
    
    'HexDump( String("HexDump of Decrypted Packet: ") , @ipkt, (eth_frame_total_size + oldSize) - 1 )

    eth1_led_on    
    eth1.start_frame
    eth1.wr_block( @ipkt, (eth_frame_total_size + oldSize) )         
    eth1.send_frame
    eth1_led_off
  else
    dbg.Str(String("That's not a encrypted packet.  To the floor with it!", 13))
    
  lockclr(eth1_op_write_lock)

PUB process_outbound | pass_unencrypted
  ' copy from eth1 (inside) to eth0 (outside)
  pass_unencrypted := 0
  eth1_led_on    
  eth1.get_frame( @opkt )
  pkt_size1 := eth1.get_rxlen
  eth1_led_on

  dbg.Str(String("eth1: ("))
  dbg.Dec(pkt_size1)
  dbg.Str(String(") "))

  ' Sanity check.  
  if (pkt_size1 > 1518)
    lockclr(eth1_op_read_lock)
    return

  'HexDump( String("HexDump of Packet: ") , @opkt, pkt_size1 )
      
  if ( test_arp( @opkt ) )
    pass_unencrypted := 1
  else
    if ( test_ip( @opkt ) )
      if ( test_udp( @opkt ) )
        if ( udp_dport( @opkt ) == udp_dhcp_port_srv )    ' pass dhcp to the server from us.
          pass_unencrypted := 1
        if ( udp_dport( @opkt ) == udp_port_dns )         ' pass DNS unless paranoid enough.
          pass_unencrypted := 1

  ' Eat the packet and consume the MAC address for our filter address on the outside.
  if ( test_icmp( @opkt ) )
    SetMACFilterOnEth0( @opkt )
    '' TODO: DO NOT ALLOW ICMP THROUGH
    '' return    

  if ( pass_unencrypted == 1 )
    no_crypt_forward_to_eth0
  else
    ' implicit else, encrypt that sucker.
    encrypt_forward_to_eth0    

  dbg.NewLine    
  lockclr(eth1_op_read_lock)
  'cogstop(cogid)
  
PUB no_crypt_forward_to_eth0
  repeat until not lockset(eth0_op_write_lock)
  
  eth0_led_on    
  eth0.start_frame
  eth0.wr_block( @opkt, pkt_size1)
  eth0.send_frame
  eth0_led_off

  lockclr(eth0_op_write_lock)

PUB encrypt_forward_to_eth0 | oldProto, oldSize, blockedSize, idx, payloadStart, payloadEnd, ii 
  repeat until not lockset(eth0_op_write_lock)

  dbg.Str(String("ENCRYPTING "))

  if(test_ip( @opkt ))
    ' Get the old protocol number
    oldProto := byte[@opkt][const_offset_ip_protocol_off] 

    'dbg.Str(String("** oldProto = "))
    'dbg.Dec(oldProto)

    ' SET IP Protocol to 99
    byte[@opkt][const_offset_ip_protocol_off] := 99 ' IPPROTO 99 is reserved for private routable encryption systems.

    ' Get the size of the IP Packet in the header
    oldSize := wordflip( word[@opkt][const_offset_ip_totallen_off/2] )

    'dbg.Str(String("** oldSize = "))
    'dbg.Dec(oldSize)

    ' Add one for the protocol preservation location, and 2 for the old size.

    ' Now calculate the AES blocking size
    blockedSize := (oldSize - ip_header_total_length)

    ' Now add the amount we need to store the old size and old protocol (3 bytes, pad 1 for word access)
    blockedSize := blockedSize + 4

    ' Now round to the AES block size.
    
    blockedSize := blockedSize + ( $0010 - (blockedSize & $000F ) ) ' This rounds to a 16 byte block size. 
    'dbg.Str(String("** blockedSize = "))
    'dbg.Dec(blockedSize)

    'dbg.Str(String("** blockedSize w/ Header = "))
    'dbg.Dec( blockedSize + ip_header_total_length )


    {
    ETH HDR : IP HDR : Payload (34 --> (ip_total_length - 20)
    14      : 20     : (Offset 34, payload size is ip_total_length - 20 for header)

    }
    ' Set the new payload size.
    word[@opkt][const_offset_ip_totallen_off/2] := wordflip( blockedSize + ip_header_total_length )

    payloadStart := eth_frame_total_size + ip_header_total_length  
    payloadEnd := eth_frame_total_size + ip_header_total_length + blockedSize  

    'dbg.Str(String("** payloadStart = "))
    'dbg.Dec(payloadStart)
    'dbg.Str(String("** payloadEnd = "))
    'dbg.Dec(payloadEnd)


    ' Preserve the old protocol inside the encrypted payload.
    byte[@opkt][(payloadEnd - 4)] := oldProto
    word[@opkt][(payloadEnd - 2)/2] := oldSize

    
    ' Reset the encryption IV
    ResetIV( @enc_iv )

    ' Do the acutal encryption in place.
    if (enable_crypto_cbc)
      aes_enc.CBCEncrypt (@opkt[payloadStart], @opkt[payloadStart], (payloadEnd - payloadStart)/16, @enc_iv)
    else
      if (enable_crypto_ecb)
        repeat ii from payloadStart to payloadEnd step 16
          aes_dec.ECBEncrypt( @opkt[ii], @opkt[ii] )

    ' Recompute the checksum.
    word[@opkt][const_offset_ip_head_csum_off/2] := 0
    word[@opkt][const_offset_ip_head_csum_off/2] := wordflip( eth0_chksum(@opkt[eth_frame_total_size], 20) )
    
    eth0_led_on    
    eth0.start_frame 
    eth0.wr_block( @opkt, pkt_size1 + ((blockedSize + ip_header_total_length) - oldSize)  )
    'eth0.wr_block( @opkt, eth_frame_total_size + ip_header_total_length )
    'eth0.wr_block( @enpkt, payloadEnd - payloadStart )    
    eth0.send_frame
    eth0_led_off
  else
    dbg.Str(String("Pkt is NOT IP.  Can not encrypt."))
  
  lockclr(eth0_op_write_lock)

PUB SetMACFilterOnEth0( pkt )
  ' ICMP packet.  Pull the clinet's MAC address out.
  ''dbg.Str(String("!!!! ICMP Ping MAC Address detected.  Setting filters !!!!", 13))
  ''return

  eth0.banksel(eth0#MAADR1)
  eth0.wr_reg(eth0#MAADR1, byte[pkt][0 + eth_frame_src_offset])
  eth0.wr_reg(eth0#MAADR2, byte[pkt][1 + eth_frame_src_offset])
  eth0.wr_reg(eth0#MAADR3, byte[pkt][2 + eth_frame_src_offset])
  eth0.wr_reg(eth0#MAADR4, byte[pkt][3 + eth_frame_src_offset])
  eth0.wr_reg(eth0#MAADR5, byte[pkt][4 + eth_frame_src_offset])
  eth0.wr_reg(eth0#MAADR6, byte[pkt][5 + eth_frame_src_offset])

  eth0.banksel(eth0#ERXFCON)
  eth0.wr_reg(eth0#ERXFCON, $A1) ' Unicast, broadcast and OR mode filtering (must match one)
  
  ' Return to the packet counter bank so we can monitor the flow.
  eth0.banksel(eth0#EPKTCNT)



PRI SetupLEDs
  ' Set the LEDS for output on the DC badge and make sure they are off.
  dira[led_eth0_activity]~~
  outa[led_eth0_activity] := 0
  dira[led_eth1_activity]~~
  outa[led_eth1_activity] := 0

  '' Crypto Status indicator(s).
  dira[led_crypto_key_present]~~                    ' LED 3 and 4 are both on if crypto is operational.
  outa[led_crypto_key_present] := 0                 
  dira[led_crypto_key_loaded]~~
  outa[led_crypto_key_loaded] := 0

  ' Pulse indicator (this has the effect of being pwm in some ways
  dira[led_pulse]~~
  outa[led_pulse] := 0

PRI ResetEthControllers
  ' Reset both controllers.
  dira [eth0_rst]~~
  dira [eth1_rst]~~

  outa[eth0_rst] := 0
  outa[eth1_rst] := 0  

  waitcnt( (clkfreq/32) + cnt )

  outa[eth0_rst] := 1
  outa[eth1_rst] := 1

  ' Wait a wee bit for the reset to complete.  
  waitcnt(clkfreq/16 + cnt)


''' These check should expand and be "fast" since they'll just look at the byte in question and return a 1/0

''' ARP packet?
PUB test_arp( pkt )
  if (word[pkt][eth_frame_type_offset/2] == eth_type_arp)
    return true
  else
    return false 

''' IP Packet?
PUB test_ip ( pkt )
  if (word[pkt][eth_frame_type_offset/2] == eth_type_ip)
    return true
  else
    return false

PUB test_udp( pkt )
  if (byte[pkt][const_offset_ip_protocol_off] == ip_proto_udp)
    return true
  else
    return false

PUB test_tcp( pkt )
  if (byte[pkt][const_offset_ip_protocol_off] == ip_proto_tcp)
    return true
  else
    return false


PUB test_icmp( pkt )
  if (byte[pkt][const_offset_ip_protocol_off] == ip_proto_icmp)
    return true
  else
    return false

PUB test_peeblocker( pkt )
  if (byte[pkt][const_offset_ip_protocol_off] == ip_proto_peeblocker)
    return true
  else
    return false


  ''' We use trickery and knowing that the compiler will drop out of the and test if it's not UDP
  ''' we can just pull the port number.  Normally, if there were GP functions we'd want to test the
  ''' whole mess again to be sure noone called it incorrectly.  Embedded is different.  It's gotta be
  ''' small before anything else...

PUB udp_sport( pkt )
  return word[pkt][const_offset_udp_sport_off/2]

PUB udp_dport( pkt )
  return word[pkt][const_offset_udp_dport_off/2]

PUB wordflip( short )
  return (( short & $FF00 ) >> 8 ) | ((short & $00FF) << 8)


PRI eth0_chksum(ptr, hdrlen) : chksum
  chksum := eth0.chksum_add(ptr, hdrlen)
  chksum := calc_chksumfinal(chksum)

PRI eth1_chksum(ptr, hdrlen) : chksum
  chksum := eth1.chksum_add(ptr, hdrlen)
  chksum := calc_chksumfinal(chksum)
  
PRI calc_chksumfinal(chksumin) : chksum
  ' Performs the final part of checksums
  chksum := (chksumin >> 16) + (chksumin & $FFFF)
  chksum := (!chksum) & $FFFF


PUB eth0_led_on
  outa[led_eth0_activity] := 1

PUB eth0_led_off
  outa[led_eth0_activity] := 0

PUB eth1_led_on
  outa[led_eth1_activity] := 1

PUB eth1_led_off
  outa[led_eth1_activity] := 0


''' Debug method only.
PUB HexDump( _hdr, _ptr, _len ) | i, j, stop
  if (_len > 128 )
    stop := 128
  else
    stop := _len

  dbg.Str(_hdr)
  dbg.NewLine
  i := 0
  j := 0
  repeat i from 0 to stop
    dbg.Str( num.hex(byte[_ptr][i], 2) )
    dbg.Str(String(" "))        
    if j == 15
      dbg.NewLine
      j := 0
    else
      j++
  dbg.NewLine

PUB ResetIV( _iv ) | ii
  repeat ii from 0 to 3
    _iv[ii] := $DC22DC22        ' In honor of DC22...  Normally this would be something else. :-)
                                                       
  
CON
  ''' These are defined as constants so that the compiler can discard anythign we don't use and save us some
  ''' tastey bytes for other things.

  ''' THESE ARE DEFINED IN LITTLE-ENDIAN ORDER (and therefor are backwards from the network byte order!!!

  ''' Ethernet Frame headed offsets and enumerations.
  eth_frame_dst_offset = 0      ' 6 bytes
  eth_frame_src_offset = 6      ' 6 bytes
  eth_frame_type_offset = 12    ' word
  eth_frame_total_size = 14     ' 14 bytes all said.

  eth_type_arp = $06_08         ' ARR packets.
  eth_type_ip = $00_08          ' IP packets
  'eth_type_arp = $08_06         ' ARR packets.
  'eth_type_ip = $08_00          ' IP packets


  ''' ARP packet offsets
  ''' All offsets are element relative to handle any weird framing protocols that this might need to run in front of.
  arp_hwtype_offset = 0         ' word
  arp_protocol_type_offset = 2  ' word
  arp_hardware_size_offset = 4  ' byte
  arp_protocol_size_offset = 5  ' byte  
  arp_opcode_offset = 6         ' word

  arp_ip_src_mac_offset = 8     ' 6 bytes
  arp_ip_sender_ip_offset = 14  ' 4 bytes for ipv4
  arp_ip_dst_mac_offset = 20    ' 6 bytes
  arp_ip_dst_ip_offset = 26     ' 4 bytes for ipv4                                         

  ''' ARP Packet Enumerations
  arp_opcode_request = $01_00   ' opcode for an arp request.
  arp_opcode_response = $02_00  ' opcode for an arp reqponse.                    
  'arp_opcode_request = $00_01   ' opcode for an arp request.
  'arp_opcode_response = $00_02  ' opcode for an arp reqponse.                    


  ''' IP header enumerations
  ''' Again all relative to 0 on the packet.
  ip_ver_len_offset = 0         ' 4bit/4bit
  ip_tos_offset = 1             ' byte
  ip_total_len_offset = 2       ' word
  ip_id_offset = 4              ' word
  ip_flags_frags = 6            ' word all together, we don't really care for our purposes.
  ip_ttl_offset = 8             ' byte
  ip_protocol_offset = 9        ' byte
  ip_header_cksum_offset = 10   ' word          
  ip_src_addr_offset = 12       ' long   
  ip_dst_addr_offset = 16       ' long
  ip_header_total_length = 20   ' Most of the time anyway.

  ip_proto_icmp = 1             ' for setting the MAC filter.
  ip_proto_tcp = 6              ' 0 is also accepted often, but it's not RFC complaint.
  ip_proto_udp = 17             ' UDP pkts for DHCP passthrough.
  ip_proto_peeblocker = 99      ' for blocking the NSA pee cams.

  udp_src_port_offset = 22      ' word
  udp_dst_port_offset = 24      ' word
  udp_dhcp_port_srv = (67<<16)  ' these are different since udp is stateless.  67 is a server response
  udp_dhcp_port_cli = (68<<16)  ' 68 is a client request
  udp_port_dns = (53<<16)       ' 53 for DNS  
  
  ''' Compact forms for constant usage to speed things up and avoid unneeded addition operations.
  const_offset_arp_opcode_off = eth_frame_total_size + arp_opcode_offset
  const_offset_ip_protocol_off = eth_frame_total_size + ip_protocol_offset
  const_offset_ip_totallen_off = eth_frame_total_size + ip_total_len_offset
  const_offset_ip_head_csum_off = eth_frame_total_size + ip_header_cksum_offset
  const_offset_udp_sport_off = eth_frame_total_size + ip_header_total_length + udp_src_port_offset
  const_offset_udp_dport_off = eth_frame_total_size + ip_header_total_length + udp_dst_port_offset