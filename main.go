package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"

	"path/filepath"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
	"golang.org/x/exp/slog"
)

type msgHandler struct {
	msg    chan []byte
	logger *slog.Logger
}

type httpStreamFactory struct {
	msgHandler
	outputDir    string
	outputPrefix string
	skipHdrs     []string
}

type httpStream struct {
	net, transport gopacket.Flow
	r              tcpreader.ReaderStream
	msgHandler
}

type reqInterceptor struct {
	data []byte
	r    tcpreader.ReaderStream
}

func NewHttpStreamFactory(logger *slog.Logger, outputDir, outputPrefix string, skipHdrs []string) *httpStreamFactory {
	return &httpStreamFactory{
		outputDir:    outputDir,
		outputPrefix: outputPrefix,
		msgHandler: msgHandler{
			msg:    make(chan []byte),
			logger: logger,
		},
		skipHdrs: skipHdrs,
	}
}

func (f *httpStreamFactory) filterHeaders(data []byte) (ret []byte) {
	if len(f.skipHdrs) == 0 {
		return data
	}
	sep := []byte{0x0d, 0x0a}
	i := bytes.Index(data, sep)
	for {
		if i == -1 {
			panic("incomplete request")
		} else if i == 0 {
			ret = append(ret, data...)
			break
		}
		line := data[:i+2]
		if len(ret) == 0 {
			// request line
			ret = append(ret, line...)
		} else {
			j := bytes.IndexByte(line, ':')
			if j == -1 {
				f.logger.Debug("unable to determine header", "line", line)
				return
			}
			header := string(bytes.ToLower(bytes.TrimSpace(line[:j])))
			if !slices.Contains(f.skipHdrs, header) {
				ret = append(ret, line...)
			}
		}
		data = data[i+2:]
		i = bytes.Index(data, sep)
	}
	return
}

func (f *httpStreamFactory) run() {
	count := 0
	for msg := range f.msg {
		if msg == nil {
			break
		}
		path := filepath.Join(f.outputDir, fmt.Sprintf("%s-%d.black", f.outputPrefix, count))
		msg := f.filterHeaders(msg)
		if err := os.WriteFile(path, msg, os.ModePerm); err != nil {
			f.logger.Error("failed to save", "path", path, "err", err)
		} else {
			count += 1
		}
	}
	f.logger.Info("saved", "output", f.outputDir, "count", count)
	close(f.msg)
}

func (f *httpStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	hs := &httpStream{
		net:        net,
		transport:  transport,
		r:          tcpreader.NewReaderStream(),
		msgHandler: f.msgHandler,
	}
	go hs.run()
	return &hs.r
}

func NewReqInterceptor(r tcpreader.ReaderStream) *reqInterceptor {
	return &reqInterceptor{r: r}
}

func (q *reqInterceptor) Read(p []byte) (n int, err error) {
	n, err = q.r.Read(p)
	if err == nil {
		q.data = append(q.data, p[:n]...)
	}
	return
}

func (q *reqInterceptor) reset() {
	q.data = []byte{}
}

func (h *httpStream) run() {
	interceptor := NewReqInterceptor(h.r)
	buf := bufio.NewReader(interceptor)
	for {
		req, err := http.ReadRequest(buf)
		if err == io.EOF {
			return
		} else if err != nil {
			h.logger.Debug("failed to read stream", "err", err)
		} else {
			n := tcpreader.DiscardBytesToEOF(req.Body)
			h.logger.Info("request", "net", h.net, "transport", h.transport, "method", req.Method, "uri", req.RequestURI, "body", n)
			req.Body.Close()
			h.msg <- interceptor.data
			interceptor.reset()
		}
	}
}

func main() {
	var (
		srcPort   int
		dstPort   int
		outputDir string
		filter    string
		level     string
		skipHdrs  string
	)
	flag.IntVar(&srcPort, "src", -1, "Filter by TCP source port number")
	flag.IntVar(&dstPort, "dst", -1, "Filter by TCP destination port number")
	flag.StringVar(&filter, "f", "", "Filter string applied to pcap, overwritten by -src or -dst")
	flag.StringVar(&outputDir, "o", "", "Output directory")
	flag.StringVar(&level, "l", "info", "Logging level")
	flag.StringVar(&skipHdrs, "skipHdrs", "host,origin,content-length", "Headers to be ignored in a case-insensitive way. Multiple header names separated by comma")
	flag.Parse()

	var filenames []string
	filenames = append(filenames, flag.Args()...)

	var slogLevel slog.Leveler
	switch strings.ToLower(level) {
	case "debug", "d":
		slogLevel = slog.LevelDebug
	default:
		slogLevel = slog.LevelInfo
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slogLevel,
	}))

	if srcPort != -1 {
		filter = fmt.Sprintf("tcp and src port %d", srcPort)
	}
	if dstPort != -1 {
		filter = fmt.Sprintf("tcp and dst port %d", dstPort)
	}

	logger.Debug("applying filter", "filter", filter)

	var wg sync.WaitGroup
	for _, f := range filenames {
		logger.Info("load", "file", f)
		dir, baseName := filepath.Split(f)
		if outputDir != "" {
			dir = outputDir
		}
		factory := NewHttpStreamFactory(logger, dir, strings.TrimSuffix(baseName, filepath.Ext(baseName)), strings.Split(skipHdrs, ","))
		pool := tcpassembly.NewStreamPool(factory)
		assembler := tcpassembly.NewAssembler(pool)

		wg.Add(1)
		go func() {
			defer wg.Done()
			factory.run()
		}()

		func() {
			handle, err := pcap.OpenOffline(f)
			if err != nil {
				logger.Error("decode failure", "file", f, "err", err)
				return
			}
			defer handle.Close()

			if filter != "" {
				if err := handle.SetBPFFilter(filter); err != nil {
					logger.Error("failed to set filter", "err", err)
					return
				}
			}

			source := gopacket.NewPacketSource(handle, handle.LinkType())
			packets := source.Packets()

			ticker := time.Tick(time.Minute)

			for {
				select {
				case packet := <-packets:
					if packet == nil {
						logger.Debug("finish reading packets")
						factory.msg <- nil
						return
					}
					if packet.NetworkLayer() == nil || packet.TransportLayer() == nil || packet.TransportLayer().LayerType() != layers.LayerTypeTCP {
						logger.Debug("unusable packet")
						continue
					}
					tcp := packet.TransportLayer().(*layers.TCP)
					assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)
				case <-ticker:
					assembler.FlushOlderThan(time.Now().Add(time.Minute - 2))
				}
			}

		}()
	}
	wg.Wait()
}
