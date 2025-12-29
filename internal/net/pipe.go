package net

import (
	"context"
	"io"
	"time"

	"github.com/go-gost/core/common/bufpool"
	xio "github.com/go-gost/x/internal/io"
)

const (
	// tcpWaitTimeout implements a TCP half-close timeout.
	tcpWaitTimeout = 10 * time.Second
	readTimeout    = 30 * time.Second
)

// Pipe 在两个连接之间建立双向数据通道
func Pipe(ctx context.Context, rw1, rw2 io.ReadWriteCloser) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	errCh := make(chan error, 2)

	// 启动两个方向的传输
	go func() {
		errCh <- pipeHalf(ctx, rw1, rw2)
	}()

	go func() {
		errCh <- pipeHalf(ctx, rw2, rw1)
	}()

	// 等待第一个错误或完成
	var firstErr error
	for i := 0; i < 2; i++ {
		select {
		case err := <-errCh:
			if firstErr == nil && err != nil {
				firstErr = err
				cancel() // 一个方向出错，取消另一个
			}
		case <-ctx.Done():
			// 超时或主动取消
			forceClose(rw1, rw2)
			return ctx.Err()
		}
	}

	return firstErr
}

// pipeHalf 单向管道传输
func pipeHalf(ctx context.Context, src, dst io.ReadWriteCloser) error {
	defer func() {
		// 传输完成后执行TCP半关闭
		halfClose(src, dst)
	}()

	buf := bufpool.Get(bufferSize / 2)
	defer bufpool.Put(buf)


	// 创建带超时的读取器
	reader := &readDeadliner{
		Reader: src,
		ctx:    ctx,
	}

	// 循环读取并写入，每次读取都有超时
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			// 设置读取超时
			if rd, ok := src.(interface{ SetReadDeadline(time.Time) error }); ok {
				rd.SetReadDeadline(time.Now().Add(readTimeout))
			}

			// 读取数据
			nr, err := reader.Read(buf)
			if err != nil {
				if err != io.EOF {
					return err
				}
				return nil // 正常结束
			}

			// 写入数据
			_, err = dst.Write(buf[:nr])
			if err != nil {
				return err
			}
		}
	}
}

// readDeadliner 包装读取器，支持上下文取消
type readDeadliner struct {
	io.Reader
	ctx context.Context
}

func (r *readDeadliner) Read(p []byte) (int, error) {
	// 检查上下文是否已取消
	select {
	case <-r.ctx.Done():
		return 0, r.ctx.Err()
	default:
	}
	return r.Reader.Read(p)
}

// halfClose 执行TCP半关闭
func halfClose(src, dst io.ReadWriteCloser) {
	// 关闭读取端
	if cr, ok := src.(xio.CloseRead); ok {
		cr.CloseRead()
	}

	// 关闭写入端，尝试半关闭
	if cw, ok := dst.(xio.CloseWrite); ok {
		if err := cw.CloseWrite(); err == xio.ErrUnsupported {
			dst.Close() // 不支持半关闭，完全关闭
		} else {
			// 设置半关闭超时
			if rd, ok := dst.(interface{ SetReadDeadline(time.Time) error }); ok {
				rd.SetReadDeadline(time.Now().Add(tcpWaitTimeout))
			}
		}
	} else {
		dst.Close() // 不支持CloseWrite，完全关闭
	}
}

// forceClose 强制关闭两个连接
func forceClose(conns ...io.ReadWriteCloser) {
	for _, conn := range conns {
		if conn != nil {
			conn.Close()
		}
	}
}
