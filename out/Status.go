package out

import "time"

type Status struct {
	start  time.Time
	end    time.Time
	async  bool
	text   string
	format Format
}

func CreateStatus(title string, async bool, format Format) Status {
	if format == "json" {
		if async {
			Print("  %s...", title)
		} else {
			PrintString("  %s...", title)
		}
	}
	return Status{
		start:  time.Now(),
		text:   title,
		async:  async,
		format: format,
	}
}
func (s *Status) Finish() {
	s.end = time.Now()
	if s.format == "json" {
		return
	}
	if s.async {
		Print("  %s %s", s.text, ColorText("FINISHED", "green"))
	} else {
		Print("%s", ColorText("FINISHED", "green"))
	}
}
