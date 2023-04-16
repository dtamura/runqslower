Runqslower
=======================

Original: https://github.com/iovisor/bcc/blob/master/libbpf-tools/runqslower.c



Setup
-------------

### build libbpf
```sh
git clone https://github.com/libbpf/libbpf.git -b v1.1.0 \
    && cd libbpf/src \
    && make \
    && mkdir build \
    && BUILD_STATIC_ONLY=y OBJDIR=build DESTDIR=/ make install
```

### install bpftool
```sh
yum install -y bpftool
```


### install golang
```sh
wget https://go.dev/dl/go1.19.6.linux-amd64.tar.gz
rm -rf /usr/local/go && tar -C /usr/local -xzf go1.19.6.linux-amd64.tar.gz
rm -rf go1.19.6.linux-amd64.tar.gz
```


### setup repo
```sh
go mod init runqslower
go get github.com/cilium/ebpf
go get github.com/shirou/gopsutil/v3/host
```

### generate vmlinux.h
```sh
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```


Build
------------------

```sh
go generate
go run -exec=sudo .
CGO_ENABLED=0 go build .
```