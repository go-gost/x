package selector

import (
	"math/rand"
	"time"
)

type randomWeightedItem[T any] struct {
	item   T
	weight int
}

type randomWeighted[T any] struct {
	items []*randomWeightedItem[T]
	sum   int
	r     *rand.Rand
}

func newRandomWeighted[T any]() *randomWeighted[T] {
	return &randomWeighted[T]{
		r: rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

func (rw *randomWeighted[T]) Add(item T, weight int) {
	ri := &randomWeightedItem[T]{item: item, weight: weight}
	rw.items = append(rw.items, ri)
	rw.sum += weight
}

func (rw *randomWeighted[T]) Next() (v T) {
	if len(rw.items) == 0 {
		return
	}
	if rw.sum <= 0 {
		return
	}
	weight := rw.r.Intn(rw.sum) + 1
	for _, item := range rw.items {
		weight -= item.weight
		if weight <= 0 {
			return item.item
		}
	}

	return rw.items[len(rw.items)-1].item
}

func (rw *randomWeighted[T]) Reset() {
	rw.items = nil
	rw.sum = 0
}
