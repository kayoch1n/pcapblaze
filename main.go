package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

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

func NewHttpStreamFactory(logger *slog.Logger, outputDir, outputPrefix string) *httpStreamFactory {
	return &httpStreamFactory{
		outputDir:    outputDir,
		outputPrefix: outputPrefix,
		msgHandler: msgHandler{
			msg:    make(chan []byte),
			logger: logger,
		},
	}
}

func (f *httpStreamFactory) run() {
	count := 0
	for msg := range f.msg {
		if msg == nil {
			break
		}
		path := filepath.Join(f.outputDir, fmt.Sprintf("%s-%d.black", f.outputPrefix, count))
		if err := os.WriteFile(path, msg, os.ModePerm); err != nil {
			f.logger.Error("failed to save", "path", path, "err", err)
		} else {
			count += 1
		}
	}
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
		interceptor.reset()
		req, err := http.ReadRequest(buf)
		if err == io.EOF {
			return
		} else if err != nil {
			h.logger.Error("failed to read stream", "err", err)
		} else {
			n := tcpreader.DiscardBytesToEOF(req.Body)
			h.logger.Info("request", "net", h.net, "transport", h.transport, "method", req.Method, "uri", req.RequestURI, "body", n)
			req.Body.Close()
		}
		h.msg <- interceptor.data
	}
}

func main() {
	var (
		srcPort   int
		dstPort   int
		outputDir string
		filter    string
		level     string
	)
	flag.IntVar(&srcPort, "src", -1, "Filter by TCP source port number")
	flag.IntVar(&dstPort, "dst", -1, "Filter by TCP destination port number")
	flag.StringVar(&filter, "f", "tcp and dst port 80", "Filter string applied to pcap, overwritten by -src or -dst")
	flag.StringVar(&outputDir, "o", "", "Output directory")
	flag.StringVar(&level, "l", "debug", "Logging level")
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

	for _, f := range filenames {
		logger.Info("load", "file", f)
		dir, baseName := filepath.Split(f)
		if outputDir != "" {
			dir = outputDir
		}
		factory := NewHttpStreamFactory(logger, dir, strings.TrimSuffix(baseName, filepath.Ext(baseName)))
		pool := tcpassembly.NewStreamPool(factory)
		assembler := tcpassembly.NewAssembler(pool)

		go factory.run()

		func() {
			handle, err := pcap.OpenOffline(f)
			if err != nil {
				logger.Error("decode failure", "file", f, "err", err)
				return
			}
			defer handle.Close()

			if err := handle.SetBPFFilter(filter); err != nil {
				logger.Error("failed to set filter", "err", err)
				return
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
}
