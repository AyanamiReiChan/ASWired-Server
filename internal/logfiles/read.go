package logfiles

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
)

type Line struct {
	File   string `json:"file"`
	Offset int64  `json:"offset"`
	Text   string `json:"text"`
}
type Tail struct {
	Lines     []Line `json:"lines"`
	Truncated bool   `json:"truncated"`
}

// Read returns newest lines first, bounded in both IO and memory. The same lock
// protects reads, writes, rotation and deletion, so deleted content cannot linger.
func (m *Manager) Read(limit int) (Tail, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := Tail{Lines: []Line{}}
	if limit < 1 {
		limit = 200
	}
	if limit > 2000 {
		limit = 2000
	}
	inventory, err := m.inventory()
	if err != nil {
		return out, err
	}
	budget := int64(2 << 20)
	for index, file := range inventory.Files {
		if err := m.regular(file.Name); err != nil {
			return out, err
		}
		f, err := m.root.Open(file.Name)
		if err != nil {
			return out, err
		}
		size := file.Size
		start := size - budget
		if start < 0 {
			start = 0
		}
		data, err := io.ReadAll(io.NewSectionReader(f, start, size-start))
		f.Close()
		if err != nil {
			return out, err
		}
		budget -= int64(len(data))
		if start > 0 {
			if cut := bytes.IndexByte(data, '\n'); cut >= 0 {
				start += int64(cut + 1)
				data = data[cut+1:]
			} else {
				data = nil
			}
			out.Truncated = true
		}
		end := len(data)
		for end > 0 {
			if data[end-1] == '\n' {
				end--
			}
			if end == 0 {
				break
			}
			begin := bytes.LastIndexByte(data[:end], '\n') + 1
			if end > begin {
				out.Lines = append(out.Lines, Line{file.Name, start + int64(begin), string(data[begin:end])})
			}
			end = begin
			if len(out.Lines) == limit {
				out.Truncated = end > 0 || start > 0 || index+1 < len(inventory.Files)
				return out, nil
			}
		}
		if budget <= 0 {
			out.Truncated = true
			break
		}
	}
	return out, nil
}

func (m *Manager) Append(event map[string]any) error {
	raw, err := json.Marshal(event)
	if err != nil {
		return err
	}
	_, err = m.Write(append(raw, '\n'))
	return err
}
func (m *Manager) Sync() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.file == nil {
		return os.ErrClosed
	}
	return m.file.Sync()
}
