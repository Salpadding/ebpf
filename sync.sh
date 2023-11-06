rsync -azvp ./ root@192.168.1.33:/home/roots/ebpf/
ssh root@192.168.1.33 'cd /home/roots/ebpf/examples/xdp && rm -rf bpf_*.go'
ssh root@192.168.1.33 'cd /home/roots/ebpf/examples/xdp && rm -rf *.o'
ssh root@192.168.1.33 'cd /home/roots/ebpf/examples/xdp && go generate && go build -buildvcs=false'
rsync -azvp root@192.168.1.33:/home/roots/ebpf/ ./

