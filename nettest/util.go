package nettest

import (
	"context"

	"golang.org/x/sync/errgroup"
)

// SplicePackets splices packets from one stack to another until the context is
// canceled.
func SplicePackets(ctx context.Context, a, b *Stack) error {
	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		return CopyPackets(ctx, a, b)
	})

	g.Go(func() error {
		return CopyPackets(ctx, b, a)
	})

	return g.Wait()
}

// CopyPackets copies packets from one stack to another until the context is
// canceled.
func CopyPackets(ctx context.Context, dst, src *Stack) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		packet, err := src.ReadPacket(ctx)
		if err != nil {
			return err
		}

		_, err = dst.WritePacket(packet)
		if err != nil {
			return err
		}
	}
}
