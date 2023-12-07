syz-rrr
=======

![Screenshot](/screenshot.png?raw=true "Screenshot")

`syz-rrr` is a full-system deterministic record and replay tool based on PANDA.

It specializes in tracing syzkaller bug reproducers but can actually record and
replay any sort of user space stimulus against a Linux kernel.

Capabilities
------------

`syz-rrr` is capable of:

- Grabbing a kernel tree and syzkaller bug reproducer from a syzbot bug URL
- Building a kernel tree and extracting its debugging info for PANDA's OSI
- Compiling out the sanitizers not necessary for the bug (to keep things fast)
- Building a userspace stimulus and extracting its symbol information
- Generating a minimal rootfs qcow2 disk image that chains into the stimulus
- Taking a snapshot at the end of the boot scrippt (just before the stimulus)
- Grabbing a deterministic PANDA record of the stimulus execution
- Replaying the PANDA record at will (gdb's rr can be attached)
- Recording a full-system function call graph (with args) across all threads
- Writing that trace in the Perfetto protobuf format
- Serving that trace as a RPC server so it can be visualized in Perfetto
- Caching every step of the way to keep things fast and interactive

Usage
-----

syz-rrr is primarily meant to be used interactively from a Jupyter notebook.

To ease the setup, a docker container is provided which can be started with:

```shell
docker build -t florentrevest/syz-rrr:latest .
docker run --network host -it florentrevest/syz-rrr:latest
```

This exposes a Jupyter runtime on port `8888` protected by the password "rrr".
Remember you can open terminals or files in the container from the Jupyter UI.

A demo notebook is available at: http://127.0.0.1:8888/notebooks/rrr.ipynb
You can use the "Run All Cells" menu to have it trace an example syzbot bug.
This can take up to one hour to run so give it some time. At the end of the
execution you can access the function call graph at https://ui.perfetto.dev/

API
---

The API can be as simple to use as this:

```python
import rrr

# Build a kernel and rootfs from a syzbot bug
kernel, rootfs = rrr.from_syzbot("c6d438f2d77f96cae7c2")

# Record the execution of that bug
record = rrr.record(kernel, rootfs)

# Trace a function call graph of that record
trace = rrr.trace(kernel, rootfs, record)

# Expose it to Perfetto
rrr.serve_trace(trace)
```

But `rootfs` and `kernel` objects can also be constructed in other ways, e.g:

```python
# Create a rootfs that will run a custom provided stimulus
rootfs = rrr.Rootfs(rrr.Stimulus("/path/to/stimulus.c"))

# Use an already-checked out kernel tree
kernel = rrr.Kernel("/path/to/linux/tree")
```

Remember that when using the the Docker container, these paths must be
expressed within the container. Therefore, you may want to map a host directory
when starting the container, e.g:

```shell
docker run --network host -v $HOME/linux/:/linux/ -it florentrevest/syz-rrr:latest
```
