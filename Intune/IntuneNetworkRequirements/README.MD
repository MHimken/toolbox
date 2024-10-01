# Intune Network Requirements

[Here's the full blog related to the script](https://manima.de/2024/08/intune-network-requirements-everything-i-learned/)

## What the INR offers

The following tests are performed by default and in this order. Details about each test and how to use this script are in the blog.

- DNS
- TCP(/UDP) connection
- HTTP(S)
- TLS/SSL

Optionally the following tests will be performed:

- CRL verification (not the actual revocation of a cert, that is done when establishing a TLS/SSL connection on a TCP port)
-- TLS/SSL Inspection (more later, but yes these two are connected)
- Custom URL list that I created using the knowledge gathered from my research
- Custom list of URLs
