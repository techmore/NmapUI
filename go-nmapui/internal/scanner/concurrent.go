package scanner

import (
	"context"
	"strings"
	"sync"
)

type Task func(ctx context.Context) error

type Pool struct {
	max int
	sem chan struct{}

	wg    sync.WaitGroup
	errMu sync.Mutex
	errs  []error
}

func NewPool(maxConcurrent int) *Pool {
	if maxConcurrent <= 0 {
		maxConcurrent = 1
	}

	return &Pool{
		max: maxConcurrent,
		sem: make(chan struct{}, maxConcurrent),
	}
}

func (p *Pool) Run(ctx context.Context, tasks []Task) []error {
	for _, task := range tasks {
		if ctx.Err() != nil {
			p.addError(ctx.Err())
			break
		}

		select {
		case p.sem <- struct{}{}:
			p.wg.Add(1)
			go func(t Task) {
				defer p.wg.Done()
				defer func() { <-p.sem }()

				if err := t(ctx); err != nil {
					p.addError(err)
				}
			}(task)
		case <-ctx.Done():
			p.addError(ctx.Err())
			break
		}
	}

	p.wg.Wait()
	return p.errs
}

type AggregateError struct {
	Errors []error
}

func (e AggregateError) Error() string {
	if len(e.Errors) == 0 {
		return ""
	}

	parts := make([]string, 0, len(e.Errors))
	for _, err := range e.Errors {
		if err == nil {
			continue
		}
		parts = append(parts, err.Error())
	}

	return strings.Join(parts, "; ")
}

func CombineErrors(errs []error) error {
	filtered := make([]error, 0, len(errs))
	for _, err := range errs {
		if err != nil {
			filtered = append(filtered, err)
		}
	}

	if len(filtered) == 0 {
		return nil
	}

	return AggregateError{Errors: filtered}
}

func (p *Pool) addError(err error) {
	if err == nil {
		return
	}

	p.errMu.Lock()
	p.errs = append(p.errs, err)
	p.errMu.Unlock()
}
