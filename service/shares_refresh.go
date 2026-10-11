package service

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"sort"
	"strings"
	"time"
)

// smbd refresh per change level:
// - main config (globals, marker upgrade, legacy migration), startup reconcile: restart
// - set of Time Machine shares changed: restart (smbd registers _adisk._tcp only at start)
// - other share create/edit/delete: reload-config, then close-share for every share whose
//   stanza changed or is gone → its clients reconnect under the new stanza (narrowed access
//   applies at once); other shares' sessions (e.g. a running backup) stay
// - accounts: nothing (passdb read per login; delete refused while a share names the account)

// changedSambaShares: names of the shares in before whose stanza differs or is gone in after.
// Added shares are not listed (no sessions to close).
func changedSambaShares(before, after []byte) []string {
	previous := sambaShareStanzas(before)
	current := sambaShareStanzas(after)
	changed := []string{}
	for key, stanza := range previous {
		if next, ok := current[key]; !ok || next.text != stanza.text {
			changed = append(changed, stanza.name)
		}
	}
	sort.Strings(changed)
	return changed
}

// timeMachineSharesChanged: a Time Machine share added, removed, or flag toggled.
func timeMachineSharesChanged(before, after []byte) bool {
	previous := sambaShareStanzas(before)
	current := sambaShareStanzas(after)
	for key, stanza := range previous {
		if stanza.timeMachine != current[key].timeMachine {
			return true
		}
	}
	for key, stanza := range current {
		if stanza.timeMachine && !previous[key].timeMachine {
			return true
		}
	}
	return false
}

type sambaShareStanza struct {
	name        string // as written in the section header (close-share argument)
	text        string // header + body
	timeMachine bool
}

// sambaShareStanzas splits a shares fragment into its sections, keyed like smbd
// resolves share names (case-insensitive).
func sambaShareStanzas(data []byte) map[string]sambaShareStanza {
	stanzas := map[string]sambaShareStanza{}
	var name string
	var text strings.Builder
	flush := func() {
		if name != "" {
			body := text.String()
			stanzas[strings.ToLower(name)] = sambaShareStanza{
				name:        name,
				text:        body,
				timeMachine: strings.Contains(body, "\nfruit:time machine = yes\n"),
			}
		}
		text.Reset()
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			flush()
			name = strings.TrimSpace(line[1 : len(line)-1])
		}
		if name != "" && line != "" {
			text.WriteString(line)
			text.WriteByte('\n')
		}
	}
	flush()
	return stanzas
}

// refreshSambaShares applies a new shares fragment without a restart. No reload
// configured, or reload failed (e.g. smbd not running): restart, the previous behaviour.
func (s *sharesStruct) refreshSambaShares(before, after []byte) error {
	if s.reloadSMBD == nil || timeMachineSharesChanged(before, after) {
		return s.restartSamba()
	}
	reloadErr := s.reloadSMBD(changedSambaShares(before, after))
	if reloadErr == nil {
		return nil
	}
	if err := s.restartSamba(); err != nil {
		return errors.Join(fmt.Errorf("reload Samba: %w", reloadErr), err)
	}
	return nil
}

// reloadSambaService: smbd re-reads its config (parent forwards to every child),
// then drops the tree connects of the given shares.
func reloadSambaService(closeShares []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := runSmbcontrol(ctx, "reload-config"); err != nil {
		return err
	}
	for _, name := range closeShares {
		if err := runSmbcontrol(ctx, "close-share", name); err != nil {
			return fmt.Errorf("close share %q: %w", name, err)
		}
	}
	return nil
}

func runSmbcontrol(ctx context.Context, arguments ...string) error {
	output := &boundedCommandOutput{limit: 8 << 10}
	command := exec.CommandContext(ctx, "smbcontrol", append([]string{"smbd"}, arguments...)...)
	command.Stdout = output
	command.Stderr = output
	if err := command.Run(); err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return errors.New("smbcontrol timed out")
		}
		return fmt.Errorf("smbcontrol %s: %w: %s", arguments[0], err, strings.TrimSpace(output.buffer.String()))
	}
	return nil
}
