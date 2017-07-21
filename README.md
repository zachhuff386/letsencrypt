# letsencrypt: simple lets encrypt certificates

First open port 80 on the server and stop any service that is using port 80.
The first command will generate an EC cert for multiple domains. The second
command will generate a 4096 RSA cert.

```
sudo python27 letsencrypt.py example1.pritunl.net example2.pritunl.net
sudo python27 letsencrypt.py --rsa example1.pritunl.net example2.pritunl.net
```