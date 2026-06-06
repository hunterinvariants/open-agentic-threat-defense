package collectors

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/open-agentic-threat-defense/oadtd/internal/domain"
)

const (
	SourceAuditd      = "auditd"
	SourceSuricataEVE = "suricata-eve"
	SourceSysmonJSON  = "sysmon-json"
	SourceZeekConn    = "zeek-conn"
)

func Normalize(source string, r io.Reader) ([]domain.Event, error) {
	switch source {
	case SourceAuditd:
		return normalizeAuditd(r)
	case SourceSuricataEVE:
		return normalizeSuricataEVE(r)
	case SourceSysmonJSON:
		return normalizeSysmonJSON(r)
	case SourceZeekConn:
		return normalizeZeekConn(r)
	default:
		return nil, fmt.Errorf("unsupported collector source %q", source)
	}
}

func Sources() []string {
	return []string{SourceAuditd, SourceSuricataEVE, SourceSysmonJSON, SourceZeekConn}
}

func scanLines(r io.Reader, handle func(lineNumber int, line string) error) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		line = strings.TrimPrefix(line, "\ufeff")
		if line == "" {
			continue
		}
		if err := handle(lineNumber, line); err != nil {
			return err
		}
	}
	return scanner.Err()
}

func normalizeAuditd(r io.Reader) ([]domain.Event, error) {
	events := []domain.Event{}
	err := scanLines(r, func(lineNumber int, line string) error {
		fields := keyValues(line)
		eventType := strings.TrimPrefix(fields["type"], "type=")
		if eventType == "" {
			if strings.Contains(line, "type=SYSCALL") {
				eventType = "SYSCALL"
			}
			if strings.Contains(line, "type=EXECVE") {
				eventType = "EXECVE"
			}
		}

		if eventType != "SYSCALL" && eventType != "EXECVE" && eventType != "USER_AUTH" && eventType != "USER_LOGIN" {
			return nil
		}

		command := firstNonEmpty(fields["cmd"], fields["comm"], fields["exe"])
		event := domain.Event{
			Kind:     domain.EventProcessStart,
			AssetID:  firstNonEmpty(fields["node"], fields["hostname"], "auditd-host"),
			Hostname: firstNonEmpty(fields["node"], fields["hostname"]),
			Process:  trimQuotes(firstNonEmpty(fields["comm"], fields["exe"])),
			Command:  trimQuotes(command),
			Signal:   "auditd " + eventType,
			Labels:   []string{"auditd", strings.ToLower(eventType)},
			Metadata: map[string]string{
				"collector":   SourceAuditd,
				"line_number": strconv.Itoa(lineNumber),
				"auid":        trimQuotes(fields["auid"]),
				"uid":         trimQuotes(fields["uid"]),
			},
		}
		if eventType == "USER_AUTH" || eventType == "USER_LOGIN" {
			event.Kind = domain.EventAuth
		}
		events = append(events, event)
		return nil
	})
	return events, err
}

func normalizeSuricataEVE(r io.Reader) ([]domain.Event, error) {
	events := []domain.Event{}
	err := scanLines(r, func(lineNumber int, line string) error {
		var eve map[string]any
		if err := json.Unmarshal([]byte(line), &eve); err != nil {
			return fmt.Errorf("line %d: %w", lineNumber, err)
		}
		eventType := stringValue(eve, "event_type")
		if eventType == "" {
			return nil
		}
		event := domain.Event{
			Timestamp:   parseTime(stringValue(eve, "timestamp")),
			Kind:        domain.EventNetworkFlow,
			AssetID:     firstNonEmpty(stringValue(eve, "host"), stringValue(eve, "src_ip"), "suricata-sensor"),
			Hostname:    stringValue(eve, "host"),
			SourceIP:    stringValue(eve, "src_ip"),
			Destination: joinHostPort(stringValue(eve, "dest_ip"), intStringValue(eve, "dest_port")),
			Signal:      "suricata " + eventType,
			Labels:      []string{"suricata", eventType},
			Metadata: map[string]string{
				"collector":   SourceSuricataEVE,
				"line_number": strconv.Itoa(lineNumber),
				"proto":       stringValue(eve, "proto"),
			},
		}
		if alert, ok := eve["alert"].(map[string]any); ok {
			event.Kind = domain.EventFinding
			event.Signal = firstNonEmpty(stringValue(alert, "signature"), event.Signal)
			event.Metadata["signature_id"] = intStringValue(alert, "signature_id")
			event.Metadata["category"] = stringValue(alert, "category")
			event.Metadata["severity"] = intStringValue(alert, "severity")
		}
		events = append(events, event)
		return nil
	})
	return events, err
}

func normalizeSysmonJSON(r io.Reader) ([]domain.Event, error) {
	events := []domain.Event{}
	err := scanLines(r, func(lineNumber int, line string) error {
		var raw map[string]any
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			return fmt.Errorf("line %d: %w", lineNumber, err)
		}
		data := flattenEventData(raw)
		eventID := firstNonEmpty(stringValue(raw, "EventID"), stringValue(raw, "event_id"), data["EventID"])
		host := firstNonEmpty(stringValue(raw, "Computer"), stringValue(raw, "Hostname"), data["Computer"], data["Hostname"])
		event := domain.Event{
			Timestamp: parseTime(firstNonEmpty(stringValue(raw, "UtcTime"), stringValue(raw, "TimeCreated"), data["UtcTime"], data["TimeCreated"])),
			Kind:      domain.EventHostObservation,
			AssetID:   firstNonEmpty(host, data["SourceIp"], data["DestinationIp"], "sysmon-host"),
			Hostname:  host,
			SourceIP:  data["SourceIp"],
			Process:   firstNonEmpty(data["Image"], data["ProcessName"]),
			Command:   data["CommandLine"],
			Signal:    "sysmon event " + eventID,
			Labels:    []string{"sysmon", "event-" + eventID},
			Metadata: map[string]string{
				"collector":   SourceSysmonJSON,
				"line_number": strconv.Itoa(lineNumber),
				"event_id":    eventID,
				"rule_name":   data["RuleName"],
			},
		}
		switch eventID {
		case "1":
			event.Kind = domain.EventProcessStart
		case "3":
			event.Kind = domain.EventNetworkFlow
			event.Destination = joinHostPort(firstNonEmpty(data["DestinationHostname"], data["DestinationIp"]), data["DestinationPort"])
		}
		events = append(events, event)
		return nil
	})
	return events, err
}

func normalizeZeekConn(r io.Reader) ([]domain.Event, error) {
	reader := bufio.NewReader(r)
	peek, err := reader.Peek(1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(peek) == 0 {
		return []domain.Event{}, nil
	}
	if peek[0] == '{' {
		return normalizeZeekConnJSON(reader)
	}
	return normalizeZeekConnTSV(reader)
}

func normalizeZeekConnJSON(r io.Reader) ([]domain.Event, error) {
	events := []domain.Event{}
	err := scanLines(r, func(lineNumber int, line string) error {
		var raw map[string]any
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			return fmt.Errorf("line %d: %w", lineNumber, err)
		}
		events = append(events, zeekConnEvent(raw, lineNumber))
		return nil
	})
	return events, err
}

func normalizeZeekConnTSV(r io.Reader) ([]domain.Event, error) {
	scanner := bufio.NewScanner(r)
	fields := []string{}
	events := []domain.Event{}
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := scanner.Text()
		if strings.HasPrefix(line, "#fields") {
			fields = strings.Fields(line)[1:]
			continue
		}
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}
		if len(fields) == 0 {
			fields = []string{"ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service"}
		}
		reader := csv.NewReader(strings.NewReader(line))
		reader.Comma = '\t'
		reader.FieldsPerRecord = -1
		parts, err := reader.Read()
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNumber, err)
		}
		raw := map[string]any{}
		for i, field := range fields {
			if i < len(parts) {
				raw[field] = parts[i]
			}
		}
		events = append(events, zeekConnEvent(raw, lineNumber))
	}
	return events, scanner.Err()
}

func zeekConnEvent(raw map[string]any, lineNumber int) domain.Event {
	sourceIP := firstNonEmpty(stringValue(raw, "id.orig_h"), stringValue(raw, "src_ip"))
	dest := firstNonEmpty(stringValue(raw, "id.resp_h"), stringValue(raw, "dest_ip"))
	port := firstNonEmpty(stringValue(raw, "id.resp_p"), intStringValue(raw, "dest_port"))
	return domain.Event{
		Timestamp:   parseZeekTime(firstNonEmpty(stringValue(raw, "ts"), stringValue(raw, "timestamp"))),
		Kind:        domain.EventNetworkFlow,
		AssetID:     firstNonEmpty(sourceIP, "zeek-sensor"),
		SourceIP:    sourceIP,
		Destination: joinHostPort(dest, port),
		Signal:      "zeek conn flow",
		Labels:      []string{"zeek", "conn"},
		Metadata: map[string]string{
			"collector":   SourceZeekConn,
			"line_number": strconv.Itoa(lineNumber),
			"uid":         stringValue(raw, "uid"),
			"proto":       stringValue(raw, "proto"),
			"service":     stringValue(raw, "service"),
		},
	}
}

func flattenEventData(raw map[string]any) map[string]string {
	result := map[string]string{}
	for key, value := range raw {
		if scalar, ok := value.(string); ok {
			result[key] = scalar
		}
	}
	if nested, ok := raw["EventData"].(map[string]any); ok {
		for key, value := range nested {
			result[key] = fmt.Sprint(value)
		}
	}
	if nested, ok := raw["event_data"].(map[string]any); ok {
		for key, value := range nested {
			result[key] = fmt.Sprint(value)
		}
	}
	return result
}

func keyValues(line string) map[string]string {
	values := map[string]string{}
	for _, part := range strings.Fields(line) {
		key, value, ok := strings.Cut(part, "=")
		if ok {
			values[key] = trimQuotes(value)
		}
	}
	return values
}

func stringValue(raw map[string]any, key string) string {
	value, ok := raw[key]
	if !ok || value == nil {
		return ""
	}
	switch typed := value.(type) {
	case string:
		return typed
	case float64:
		if typed == float64(int64(typed)) {
			return strconv.FormatInt(int64(typed), 10)
		}
		return strconv.FormatFloat(typed, 'f', -1, 64)
	default:
		return fmt.Sprint(typed)
	}
}

func intStringValue(raw map[string]any, key string) string {
	value := stringValue(raw, key)
	if value == "<nil>" {
		return ""
	}
	return value
}

func parseTime(value string) time.Time {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}
	}
	formats := []string{time.RFC3339Nano, time.RFC3339, "2006-01-02 15:04:05.999", "2006-01-02 15:04:05"}
	for _, format := range formats {
		parsed, err := time.Parse(format, value)
		if err == nil {
			return parsed.UTC()
		}
	}
	return time.Time{}
}

func parseZeekTime(value string) time.Time {
	if value == "" {
		return time.Time{}
	}
	if seconds, err := strconv.ParseFloat(value, 64); err == nil {
		whole, fraction := int64(seconds), seconds-float64(int64(seconds))
		return time.Unix(whole, int64(fraction*1e9)).UTC()
	}
	return parseTime(value)
}

func joinHostPort(host string, port string) string {
	host = strings.TrimSpace(host)
	port = strings.TrimSpace(port)
	if host == "" {
		return ""
	}
	if port == "" || port == "-" {
		return host
	}
	return host + ":" + port
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" && value != "-" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func trimQuotes(value string) string {
	return strings.Trim(value, `"`)
}
