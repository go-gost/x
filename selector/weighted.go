package selector

import (
	"math/rand"
	"time"
)

type randomWeightedItem[T any] struct {
	item   T
	weight int
}

type RandomWeighted[T any] struct {
	items []*randomWeightedItem[T]
	sum   int
	r     *rand.Rand
}

func NewRandomWeighted[T any]() *RandomWeighted[T] {
	return &RandomWeighted[T]{
		r: rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

func (rw *RandomWeighted[T]) Add(item T, weight int) {
	ri := &randomWeightedItem[T]{item: item, weight: weight}
	rw.items = append(rw.items, ri)
	rw.sum += weight
}

func (rw *RandomWeighted[T]) Next() (v T) {
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

func (rw *RandomWeighted[T]) Reset() {
	rw.items = nil
	rw.sum = 0
}
