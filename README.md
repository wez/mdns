# wez-mdns

This is a Rust crate that implements [Multicast DNS](https://en.wikipedia.org/wiki/Multicast_DNS) resolution.

Why not the `mdns` crate?  This one has a couple of important differences:

* *Tolerant of non-comformant DNS names* - there are devices that implement
  mDNS discovery but that report non-comformant names. Rather than erroring
  out, those names are returned back to the caller.
* *High Fidelity Query Responses* - this implementation returns the
  *additional* data portion from the mDNS query responses which are important for
  correctly resolving some services

