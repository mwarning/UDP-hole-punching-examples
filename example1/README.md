A simple UDP hole punching example originally taken from
http://www.rapapaing.com/blog/?p=24.
To use it you need to set SRV_IP in client_udp.c.

A drawback is that it always punches the one port
that the server is using to talk to the other client.
It would be better to test the ports above that port
for a higher success rate.
