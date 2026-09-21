package logfiles

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestRotationAndClear(t *testing.T) {
	dir := t.TempDir()
	m, err := Open(dir, 16, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	for i := 0; i < 8; i++ {
		if _, err = m.Write([]byte("123456789\n")); err != nil {
			t.Fatal(err)
		}
	}
	list, err := m.List()
	if err != nil || len(list.Files) != 3 || list.TotalSize != 30 || !list.Files[0].Active {
		t.Fatalf("rotation: %+v %v", list, err)
	}
	if err = m.Delete(list.Files[1].Name); err != nil {
		t.Fatal(err)
	}
	if err = m.Delete(ActiveName); err != nil {
		t.Fatal(err)
	}
	if _, err = m.Write([]byte("next\n")); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, ActiveName))
	if err != nil || string(raw) != "next\n" {
		t.Fatalf("write after truncate: %q %v", raw, err)
	}
	if err = m.Clear(); err != nil {
		t.Fatal(err)
	}
	list, err = m.List()
	if err != nil || len(list.Files) != 1 || list.TotalSize != 0 {
		t.Fatalf("clear: %+v %v", list, err)
	}
	if _, err = m.Write([]byte("new\n")); err != nil {
		t.Fatal(err)
	}
	if err = m.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = m.Write([]byte("closed")); !errors.Is(err, os.ErrClosed) {
		t.Fatal(err)
	}
}
func TestPathAndSymlinkProtection(t *testing.T) {
	dir := t.TempDir()
	m, err := Open(dir, 64, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	outside := filepath.Join(t.TempDir(), "secret")
	if err = os.WriteFile(outside, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"../secret", outside, "aswired.log/../secret", "other.log", ""} {
		if err = m.Delete(name); !errors.Is(err, ErrName) {
			t.Fatalf("accepted %q: %v", name, err)
		}
	}
	link := "aswired-00000000000000000001.log"
	if err = os.Symlink(outside, filepath.Join(dir, link)); err != nil {
		t.Log("symlinks unavailable:", err)
	} else {
		if err = m.Delete(link); !errors.Is(err, ErrName) {
			t.Fatalf("accepted symlink: %v", err)
		}
		if err = m.Clear(); err != nil {
			t.Fatal(err)
		}
		raw, _ := os.ReadFile(outside)
		if string(raw) != "keep" {
			t.Fatal("modified outside file")
		}
	}
}
func TestConcurrentClearAndWrite(t *testing.T) {
	m, err := Open(t.TempDir(), 64, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	var group sync.WaitGroup
	for i := 0; i < 4; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for j := 0; j < 50; j++ {
				if _, err := m.Write([]byte("message\n")); err != nil {
					t.Error(err)
				}
				if j%7 == 0 {
					if err := m.Clear(); err != nil {
						t.Error(err)
					}
				}
			}
		}()
	}
	group.Wait()
	if _, err = m.Write([]byte("still writing\n")); err != nil {
		t.Fatal(err)
	}
	list, err := m.List()
	if err != nil || list.TotalSize == 0 || len(list.Files) > 3 {
		t.Fatalf("bad inventory: %+v %v", list, err)
	}
}
