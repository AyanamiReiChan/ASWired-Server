package httpapi

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
)

// Relays describe externally configured forwarding. They never create Agent tasks
// or modify the node's authoritative connection credentials.
func relayAddress(raw string) (string, error) {
	host, port, err := net.SplitHostPort(strings.TrimSpace(raw))
	if err != nil {
		return "", errors.New("中转地址须为主机:端口，IPv6 请使用方括号")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", errors.New("中转端口须为1至65535")
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if ip := net.ParseIP(host); ip != nil {
		host = ip.String()
	} else if _, err = realityDomain(host); err != nil {
		return "", errors.New("中转主机须为IP或完整域名")
	}
	return net.JoinHostPort(host, strconv.Itoa(n)), nil
}

func (a *App) validateRelay(ctx context.Context, id string, row map[string]any) error {
	nodeID := text(row, "nodeId")
	if nodeID == "" || id != nodeID {
		return errors.New("请选择原节点，每个节点只能配置一个中转入口")
	}
	node, err := a.DB.GetRecord(ctx, "nodes", nodeID)
	if err != nil {
		return errors.New("原节点不存在")
	}
	original, err := nodeTestAddress(node.Data)
	if err != nil {
		return err
	}
	original, err = relayAddress(original)
	if err != nil {
		return err
	}
	entry, err := relayAddress(text(row, "relayAddress"))
	if err != nil {
		return err
	}
	if entry == original {
		return errors.New("中转地址不能与原服务器地址相同")
	}
	row["originalAddress"], row["relayAddress"] = original, entry
	return nil
}

func (a *App) relayEntry(ctx context.Context, nodeID, original string) (string, error) {
	row, err := a.DB.GetRecord(ctx, "relays", nodeID)
	if errors.Is(err, store.ErrNotFound) {
		return original, nil
	}
	if err != nil {
		return "", err
	}
	normalized, err := relayAddress(original)
	if err != nil {
		return "", err
	}
	// A source sync may move a node. Never silently send its credentials through
	// an old relay to a different destination.
	if normalized != text(row.Data, "originalAddress") {
		return original, nil
	}
	return relayAddress(text(row.Data, "relayAddress"))
}

func (a *App) relayClient(ctx context.Context, nodeID string, node clientNode) (clientNode, error) {
	original := net.JoinHostPort(strings.Trim(node.Host, "[]"), strconv.Itoa(node.Port))
	entry, err := a.relayEntry(ctx, nodeID, original)
	if err != nil {
		return clientNode{}, err
	}
	node.Host, entry, err = net.SplitHostPort(entry)
	if err != nil {
		return clientNode{}, err
	}
	node.Port, err = strconv.Atoi(entry)
	return node, err
}
