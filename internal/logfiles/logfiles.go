// Package logfiles owns the controller's bounded runtime log directory.
package logfiles

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
	"time"
)

const ActiveName = "aswired.log"

var ErrName = errors.New("invalid log file name")
var archiveName = regexp.MustCompile(`^aswired-[0-9]{20}\.log$`)

type File struct {
	Name       string    `json:"name"`
	Size       int64     `json:"size"`
	ModifiedAt time.Time `json:"modifiedAt"`
	Active     bool      `json:"active"`
}
type Inventory struct {
	Directory   string `json:"directory"`
	Files       []File `json:"files"`
	TotalSize   int64  `json:"totalSize"`
	MaxSize     int64  `json:"maxSize"`
	MaxArchives int    `json:"maxArchives"`
}
type Manager struct {
	name      string
	archive   *regexp.Regexp
	mu        sync.Mutex
	root      *os.Root
	file      *os.File
	directory string
	maxSize   int64
	archives  int
	closed    bool
}

func Open(directory string, maxSize int64, archives int) (*Manager, error) {
	return OpenNamed(directory, ActiveName, maxSize, archives)
}
func OpenNamed(directory, name string, maxSize int64, archives int) (*Manager, error) {
	if !regexp.MustCompile(`^[a-z][a-z0-9-]*\.log$`).MatchString(name) {
		return nil, ErrName
	}
	if maxSize <= 0 || archives < 1 {
		return nil, errors.New("invalid log rotation limits")
	}
	directory, err := filepath.Abs(directory)
	if err != nil {
		return nil, err
	}
	if err = os.MkdirAll(directory, 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("invalid log directory")
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, err
	}
	m := &Manager{root: root, directory: directory, maxSize: maxSize, archives: archives, name: name, archive: regexp.MustCompile(`^` + regexp.QuoteMeta(name[:len(name)-4]) + `-[0-9]{20}\.log$`)}
	if err = m.openActive(); err != nil {
		root.Close()
		return nil, err
	}
	if err = m.prune(); err != nil {
		m.Close()
		return nil, err
	}
	return m, nil
}
func (m *Manager) regular(name string) error {
	if name != m.name && !m.archive.MatchString(name) {
		return ErrName
	}
	info, err := m.root.Lstat(name)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return ErrName
	}
	return nil
}
func (m *Manager) openActive() error {
	if err := m.regular(m.name); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := m.root.OpenFile(m.name, os.O_CREATE|os.O_WRONLY, 0600)
	if err == nil {
		m.file = f
	}
	return err
}
func (m *Manager) inventory() (Inventory, error) {
	out := Inventory{Directory: m.directory, Files: []File{}, MaxSize: m.maxSize, MaxArchives: m.archives}
	if m.closed {
		return out, os.ErrClosed
	}
	dir, err := m.root.Open(".")
	if err != nil {
		return out, err
	}
	defer dir.Close()
	entries, err := dir.ReadDir(-1)
	if err != nil {
		return out, err
	}
	for _, entry := range entries {
		name := entry.Name()
		if name != m.name && !m.archive.MatchString(name) {
			continue
		}
		info, err := entry.Info()
		if name == m.name && m.file != nil {
			info, err = m.file.Stat()
		}
		if err != nil {
			return out, err
		}
		if !info.Mode().IsRegular() {
			continue
		}
		out.Files = append(out.Files, File{name, info.Size(), info.ModTime().UTC(), name == m.name})
		out.TotalSize += info.Size()
	}
	sort.Slice(out.Files, func(i, j int) bool {
		if out.Files[i].Active != out.Files[j].Active {
			return out.Files[i].Active
		}
		return out.Files[i].Name > out.Files[j].Name
	})
	return out, nil
}
func (m *Manager) List() (Inventory, error) { m.mu.Lock(); defer m.mu.Unlock(); return m.inventory() }
func (m *Manager) prune() error {
	out, err := m.inventory()
	if err != nil {
		return err
	}
	count := 0
	for _, file := range out.Files {
		if file.Active {
			continue
		}
		count++
		if count > m.archives {
			if err = m.root.Remove(file.Name); err != nil {
				return err
			}
		}
	}
	return nil
}
func (m *Manager) Write(p []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.file == nil {
		return 0, os.ErrClosed
	}
	if int64(len(p)) > m.maxSize {
		return 0, errors.New("log record exceeds rotation limit")
	}
	info, err := m.file.Stat()
	if err != nil {
		return 0, err
	}
	if info.Size() > 0 && info.Size()+int64(len(p)) > m.maxSize {
		if err = m.file.Close(); err != nil {
			return 0, err
		}
		m.file = nil
		name := fmt.Sprintf("%s-%020d.log", m.name[:len(m.name)-4], time.Now().UnixNano())
		if err = m.root.Rename(m.name, name); err != nil {
			_ = m.openActive()
			return 0, err
		}
		if err = m.openActive(); err != nil {
			return 0, err
		}
		if err = m.prune(); err != nil {
			return 0, err
		}
	}
	if _, err = m.file.Seek(0, io.SeekEnd); err != nil {
		return 0, err
	}
	return m.file.Write(p)
}

// Delete truncates the open active file, so future writes keep the same descriptor.
func (m *Manager) Delete(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return os.ErrClosed
	}
	return m.remove(name)
}
func (m *Manager) remove(name string) error {
	if err := m.regular(name); err != nil {
		return err
	}
	if name == m.name {
		if m.file == nil {
			return os.ErrClosed
		}
		return m.file.Truncate(0)
	}
	return m.root.Remove(name)
}
func (m *Manager) Clear() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	out, err := m.inventory()
	if err != nil {
		return err
	}
	for _, file := range out.Files {
		if err = m.remove(file.Name); err != nil {
			return err
		}
	}
	return nil
}
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil
	}
	m.closed = true
	var err error
	if m.file != nil {
		err = m.file.Close()
	}
	return errors.Join(err, m.root.Close())
}
