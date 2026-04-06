package registry

import (
	"fmt"
	"strings"

	"github.com/sokhiaryan/ak-47/internal/engine"
)

type Registry struct {
	modules map[string]engine.Module
}

func New() *Registry {
	return &Registry{
		modules: make(map[string]engine.Module),
	}
}

func (r *Registry) Register(mod engine.Module) error {
	meta := mod.Metadata()
	if meta.Name == "" {
		return engine.ErrInvalidModule
	}

	lowerName := strings.ToLower(meta.Name)
	if _, exists := r.modules[lowerName]; exists {
		return engine.ErrModuleExists
	}

	r.modules[lowerName] = mod
	return nil
}

func (r *Registry) Get(name string) (engine.Module, error) {
	lowerName := strings.ToLower(name)
	mod, exists := r.modules[lowerName]
	if !exists {
		return nil, engine.ErrModuleNotFound
	}
	return mod, nil
}

func (r *Registry) List() []engine.Module {
	modules := make([]engine.Module, 0, len(r.modules))
	for _, mod := range r.modules {
		modules = append(modules, mod)
	}
	return modules
}

func (r *Registry) Search(query string) []engine.Module {
	query = strings.ToLower(query)
	results := make([]engine.Module, 0)

	for _, mod := range r.modules {
		meta := mod.Metadata()
		if strings.Contains(strings.ToLower(meta.Name), query) ||
			strings.Contains(strings.ToLower(meta.Description), query) {
			results = append(results, mod)
		}
	}

	return results
}

func (r *Registry) ListByPhase(phase engine.Phase) []engine.Module {
	results := make([]engine.Module, 0)
	for _, mod := range r.modules {
		if mod.Metadata().Phase == phase {
			results = append(results, mod)
		}
	}
	return results
}

func (r *Registry) Count() int {
	return len(r.modules)
}

type RegistryError struct {
	Module string
	Err    error
}

func (e *RegistryError) Error() string {
	return fmt.Sprintf("module %s: %v", e.Module, e.Err)
}

func (e *RegistryError) Unwrap() error {
	return e.Err
}
