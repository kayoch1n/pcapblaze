# pcapblaze

将 pcap 包中的 HTTP 请求提取出来作为 [blazehttp](https://github.com/chaitin/blazehttp) 的用例，进而用来测试WAF的防护效果

## Build

```bash
go build -o pcapblaze
```

## Usage

```bash
# 默认提取目的端口为 80 的请求
./pcapblaze tmp1.pcap tmp2.pcap
# 提取源端口为 42592 的请求
./pcapblaze -src 42592 tmp.pcap
./pcapblaze -f "tcp and src port 42592" tmp.pcap
```

