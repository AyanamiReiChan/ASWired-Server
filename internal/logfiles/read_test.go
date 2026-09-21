package logfiles

import (
	"strings"
	"testing"
)

func TestFileTailRotationDeletionAndStreamIsolation(t *testing.T) {
	dir := t.TempDir()
	m, err := OpenNamed(dir, "agent.log", 12, 3)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	other, err := OpenNamed(dir, "security.log", 1024, 3)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	other.Write([]byte("protected\n"))
	for _, line := range []string{"one\n", "two\n", "three\n", "four\n"} {
		if _, err = m.Write([]byte(line)); err != nil {
			t.Fatal(err)
		}
	}
	tail, err := m.Read(3)
	if err != nil || len(tail.Lines) != 3 || tail.Lines[0].Text != "four" || tail.Lines[2].Text != "two" || !tail.Truncated {
		t.Fatalf("tail %+v %v", tail, err)
	}
	if err = m.Delete("security.log"); err != ErrName {
		t.Fatal("cross-stream deletion", err)
	}
	if err = m.Clear(); err != nil {
		t.Fatal(err)
	}
	tail, err = m.Read(200)
	if err != nil || len(tail.Lines) != 0 {
		t.Fatal("deleted lines remained", tail, err)
	}
	if _, err = m.Write([]byte("new\n")); err != nil {
		t.Fatal(err)
	}
	tail, _ = m.Read(200)
	if len(tail.Lines) != 1 || tail.Lines[0].Text != "new" {
		t.Fatal(tail)
	}
	keep, _ := other.Read(200)
	if len(keep.Lines) != 1 || keep.Lines[0].Text != "protected" {
		t.Fatal("other stream changed")
	}
}
func TestTailBoundsLargeFile(t *testing.T) {
	m, e := Open(t.TempDir(), 4<<20, 2)
	if e != nil {
		t.Fatal(e)
	}
	defer m.Close()
	m.Write([]byte(strings.Repeat("x", (2<<20)+10) + "\nlast\n"))
	tail, e := m.Read(200)
	if e != nil || !tail.Truncated || len(tail.Lines) != 1 || tail.Lines[0].Text != "last" {
		t.Fatal(tail, e)
	}
}
