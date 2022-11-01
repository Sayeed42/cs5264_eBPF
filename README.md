# CS5264_eBPF
## Dependencies
For eBPF programs:
```
sudo apt-get install gpg curl tar xz make gcc flex bison libssl-dev libelf-dev llvm clang libbpf-dev
```

## Building
```
make
```

## Attaching
```
sudo ./attach.sh
```
`bpf_printk` functions can be added to the BPF programs to test the attachment success. But the best way is to run this after attaching:
```
bpftool prog show
```

## Detaching
```
sudo ./detach.sh
```

## Cleaning
```
make clean
```