package out

import "time"

type Status struct {
	start time.Time
	end   time.Time
	async bool
	text  string
}

func CreateStatus(title string, async bool) Status {
	if async {
		Print("  %s...", title)
	} else {
		PrintString("  %s...", title)
	}
	return Status{
		start: time.Now(),
		text:  title,
		async: async,
	}
}
func (s *Status) Finish() {
	s.end = time.Now()
	if s.async {
		Print("  %s %s", s.text, ColorText("FINISHED", "green"))
	} else {
		Print("%s", ColorText("FINISHED", "green"))
	}
}
