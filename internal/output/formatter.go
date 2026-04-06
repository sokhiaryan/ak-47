package output

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/sokhiaryan/ak-47/internal/engine"
)

type Formatter interface {
	Format(result engine.Result) string
}

type TextFormatter struct{}

func (f *TextFormatter) Format(result engine.Result) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("[%s] %s\n", result.Module, result.Timestamp))
	sb.WriteString(fmt.Sprintf("Target: %s\n", result.Target))

	if result.Success {
		sb.WriteString("Status: SUCCESS\n")
	} else {
		sb.WriteString("Status: FAILED\n")
	}

	sb.WriteString(fmt.Sprintf("Message: %s\n", result.Message))

	if len(result.MITRE) > 0 {
		sb.WriteString(fmt.Sprintf("MITRE: %s\n", strings.Join(result.MITRE, ", ")))
	}

	if result.Data != nil {
		sb.WriteString("Results:\n")
		sb.WriteString(fmt.Sprintf("%v\n", result.Data))
	}

	if len(result.Errors) > 0 {
		sb.WriteString("Errors:\n")
		for _, err := range result.Errors {
			sb.WriteString(fmt.Sprintf("  - %s\n", err))
		}
	}

	return sb.String()
}

type JSONFormatter struct {
	Pretty bool
}

func (f *JSONFormatter) Format(result engine.Result) string {
	if f.Pretty {
		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return fmt.Sprintf(`{"error": "failed to format result: %v"}`, err)
		}
		return string(data)
	}

	data, err := json.Marshal(result)
	if err != nil {
		return fmt.Sprintf(`{"error": "failed to format result: %v"}`, err)
	}
	return string(data)
}

func GetFormatter(format string) Formatter {
	switch strings.ToLower(format) {
	case "json":
		return &JSONFormatter{Pretty: false}
	case "json-pretty":
		return &JSONFormatter{Pretty: true}
	default:
		return &TextFormatter{}
	}
}
