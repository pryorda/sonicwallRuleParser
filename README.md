# Sonicwall Rule Parser
Parses Sonicwall Rules, Groups, and Services from a settings export file.

# Example Usage
python ./parser.py sampleExport.exp
```
==========================================================
================== Firewall Rules ========================
==========================================================

Source Zone,Dest Zone,Source Net,Dest Net, Dest Service, Action, Comment
LAN,WAN,Any,Blaze Meter Group,HTTP,Allow,ExampleRule

==========================================================
================== Address Objects =======================
==========================================================

Address Name,Zone,IP,Subnet
Blaze Meter Group,WAN,0.0.0.0,0.0.0.0
BlazeMeter 1 (US East),WAN,204.222.243.199,255.255.255.255
BlazeMeter 2 (US East),WAN,204.222.243.199,255.255.255.255

==========================================================
================== Address Groups ========================
==========================================================

Blaze Meter Group
        BlazeMeter 1 (US East)
        BlazeMeter 2 (US East)


==========================================================
================== Service Objects =======================
==========================================================

Service Name, Start Port, EndPort, Protocol, ObjectType

==========================================================
================== Service Groups ========================
==========================================================
```
