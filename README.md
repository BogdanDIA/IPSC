##PROJECT: MotoTRB IPSC dissector
**This is a wireshark dissector for IP Site Connect as it is presented in https://github.com/n0mjs710/IPSC/blob/master/README.md**

###HowTo:

**The dissector is a wireshark as built-in:**

  Step 1: Download and build sources of a stable version of wireshark from www.wireshark.com
  Step 2: Copy packet-ipsc.c to DIR/epan/dissectors/
  Step 3: Modify DIR/epan/dissectors/Makefile.common to include packet-ipsc.c
    ...
    packet-ipsc.c     \
    packet-ipsi-ctl.c \
    packet-ipv6.c   \
    ...
  Step 4: Add call to IPSC in generate.c
    ...
    {extern void proto_register_ipsc (void); if(cb) (*cb)(RA_REGISTER, "proto_register_ipsc", client_data); proto_register_ipsc ();}
    ...
  Step 5:
  
