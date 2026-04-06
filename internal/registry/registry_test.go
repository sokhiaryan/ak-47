package registry

import (
	"testing"

	"github.com/sokhiaryan/ak-47/internal/engine"
)

type mockModule struct {
	meta engine.ModuleMetadata
}

func (m *mockModule) Metadata() engine.ModuleMetadata {
	return m.meta
}

func (m *mockModule) Configure(options map[string]string) error {
	return nil
}

func (m *mockModule) Execute(target string, opts engine.Options) engine.Result {
	return engine.Result{Success: true, Module: m.meta.Name}
}

func TestRegistry_Register(t *testing.T) {
	r := New()

	mod := &mockModule{
		meta: engine.ModuleMetadata{
			Name:        "test-module",
			Description: "Test module",
			Phase:       engine.PhaseReconnaissance,
		},
	}

	err := r.Register(mod)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if r.Count() != 1 {
		t.Errorf("expected 1 module, got %d", r.Count())
	}
}

func TestRegistry_Register_Duplicate(t *testing.T) {
	r := New()

	mod := &mockModule{
		meta: engine.ModuleMetadata{
			Name:        "test-module",
			Description: "Test module",
			Phase:       engine.PhaseReconnaissance,
		},
	}

	r.Register(mod)

	err := r.Register(mod)
	if err != engine.ErrModuleExists {
		t.Errorf("expected ErrModuleExists, got %v", err)
	}
}

func TestRegistry_Get(t *testing.T) {
	r := New()

	mod := &mockModule{
		meta: engine.ModuleMetadata{
			Name:        "test-module",
			Description: "Test module",
			Phase:       engine.PhaseReconnaissance,
		},
	}

	r.Register(mod)

	got, err := r.Get("test-module")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if got.Metadata().Name != "test-module" {
		t.Errorf("expected test-module, got %s", got.Metadata().Name)
	}
}

func TestRegistry_Get_NotFound(t *testing.T) {
	r := New()

	_, err := r.Get("non-existent")
	if err != engine.ErrModuleNotFound {
		t.Errorf("expected ErrModuleNotFound, got %v", err)
	}
}

func TestRegistry_List(t *testing.T) {
	r := New()

	mods := []engine.Module{
		&mockModule{meta: engine.ModuleMetadata{Name: "mod1", Phase: engine.PhaseReconnaissance}},
		&mockModule{meta: engine.ModuleMetadata{Name: "mod2", Phase: engine.PhaseExploitation}},
	}

	for _, mod := range mods {
		r.Register(mod)
	}

	list := r.List()
	if len(list) != 2 {
		t.Errorf("expected 2 modules, got %d", len(list))
	}
}

func TestRegistry_Search(t *testing.T) {
	r := New()

	mods := []engine.Module{
		&mockModule{meta: engine.ModuleMetadata{Name: "port-scanner", Description: "TCP port scanner"}},
		&mockModule{meta: engine.ModuleMetadata{Name: "http-scanner", Description: "HTTP enumeration"}},
	}

	for _, mod := range mods {
		r.Register(mod)
	}

	results := r.Search("port")
	if len(results) != 1 {
		t.Errorf("expected 1 result, got %d", len(results))
	}

	if results[0].Metadata().Name != "port-scanner" {
		t.Errorf("expected port-scanner, got %s", results[0].Metadata().Name)
	}
}

func TestRegistry_ListByPhase(t *testing.T) {
	r := New()

	mods := []engine.Module{
		&mockModule{meta: engine.ModuleMetadata{Name: "mod1", Phase: engine.PhaseReconnaissance}},
		&mockModule{meta: engine.ModuleMetadata{Name: "mod2", Phase: engine.PhaseReconnaissance}},
		&mockModule{meta: engine.ModuleMetadata{Name: "mod3", Phase: engine.PhaseExploitation}},
	}

	for _, mod := range mods {
		r.Register(mod)
	}

	recon := r.ListByPhase(engine.PhaseReconnaissance)
	if len(recon) != 2 {
		t.Errorf("expected 2 reconnaissance modules, got %d", len(recon))
	}
}
