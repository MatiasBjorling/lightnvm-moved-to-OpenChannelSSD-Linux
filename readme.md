# LightNVM: An Open-Channel FTL for LightNVM compatible Solid State Drives

**Branches**
 - master: Current *stable* version of the open-channel FTL lightnvm code.
 - lightnvm-next: Current development branch for creating the open-channel FTL for lightnvm compatible devices.
 - lightnvm: Historical branch for the work presented at the Non-Volatile Memory Workshop 2014. Found in the paper and presentation: LightNVM: Lightning Fast Evaluation Platform for Non-Volatile Memories

LightNVM implements the internal logic of SSDs within the host system. It's idea is similar to implementations found in Vidident and FusionIO VSL layers. However, this is definded in an open way, that allows many vendors to add support for open-channel SSDs. 

First iteration will allow NVMe devices to hook into the LightNVM FTL, and RapidIO SRIO coming in the near future.

This includes logic such as translation tables for logical to physical address translation, garbage collection and wear-leveling.

It is designed to be used either standalone or with a LightNVM
compatible device and firmware. 

The current version is WIP and does **not** yet work. When there is a workable version available, it will be put into the master branch.
