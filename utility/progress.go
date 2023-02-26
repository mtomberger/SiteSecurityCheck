package utility

import (
	"fmt"
	"github.com/vbauerster/mpb/v8"
	"github.com/vbauerster/mpb/v8/decor"
	"sync"
	"time"
)

const ProgressBarWidth = 8

type Progress interface {
	AddBar(text string) ProgressBar
	Wait()
	Finish()
}
type ProgressBar interface {
	Finish()
}

func CreateProgressBarForWaitGroup(wg *sync.WaitGroup) Progress {
	return StandardProgress{
		HasWaitGroup: true,
		WaitGroup:    wg,
	}
	/*
		return MpbProgress{
			progress: mpb.New(
				mpb.WithWaitGroup(wg),
				mpb.WithWidth(ProgressBarWidth),
			),
			hasWaitGroup: true,
		}
	*/
}
func CreateProgressBar(text string) Progress {

	p := StandardProgress{
		HasWaitGroup: false,
		WaitGroup:    nil,
		Bars:         []StandardProgressBar{},
	}

	p.AddBar(text)
	return p
	/*
		p := MpbProgress{
			progress: mpb.New(
				mpb.WithWidth(ProgressBarWidth),
			),
			hasWaitGroup: false,
		}
		p.AddBar(text)
		return p
	*/
}

type StandardProgress struct {
	HasWaitGroup bool
	WaitGroup    *sync.WaitGroup
	Bars         []StandardProgressBar
}
type StandardProgressBar struct {
	Start    time.Time
	Stop     time.Time
	Text     string
	Progress StandardProgress
}

func (p StandardProgress) AddBar(text string) ProgressBar {
	lb := ""
	if p.HasWaitGroup {
		lb = "\n"
	}
	fmt.Printf("  %s...%s", text, lb)
	bar := StandardProgressBar{
		Start:    time.Now(),
		Text:     text,
		Progress: p,
	}
	p.Bars = append(p.Bars, bar)
	return bar
}
func (p StandardProgress) Wait() {
	if p.HasWaitGroup {
		p.WaitGroup.Wait()
	}
}
func (p StandardProgress) Finish() {
	for _, b := range p.Bars {
		b.Finish()
	}
}
func (b StandardProgressBar) Finish() {
	b.Stop = time.Now()
	if b.Progress.HasWaitGroup {
		fmt.Printf("  %s finished\n", b.Text)
	} else {
		fmt.Printf("...finished\n")
	}

}

type MpbProgress struct {
	progress     *mpb.Progress
	hasWaitGroup bool
	bars         []MpbProgressBar
}
type MpbProgressBar struct {
	bar   *mpb.Bar
	start time.Time
}

func (p MpbProgress) AddBar(text string) ProgressBar {
	bar := MpbProgressBar{
		bar: p.progress.New(-1, spinnerStyle(),
			mpb.PrependDecorators(
				decor.OnComplete(decor.Name(text), ""),
			),
			mpb.AppendDecorators(
				decor.OnComplete(decor.Name(" "), ""),
				decor.Elapsed(decor.ET_STYLE_GO, decor.WCSyncWidth),
			),
		),
		start: time.Now(),
	}
	p.bars = append(p.bars, bar)
	return bar
}
func (p MpbProgress) Wait() {
	if p.hasWaitGroup {
		p.progress.Wait()
	} else {
		for _, b := range p.bars {
			b.Finish()
		}
	}
}
func (p MpbProgress) Finish() {
	for _, b := range p.bars {
		b.Finish()
	}
}
func (b MpbProgressBar) Finish() {
	b.bar.EwmaIncrement(time.Since(b.start))
	b.bar.SetTotal(1, true)
}
func getSpinnerFrames() []string {
	var frames []string
	act := "●"
	pass := "∙"
	for i := 0; i <= ProgressBarWidth-2+2; i++ {
		phase := ""
		for j := 0; j <= ProgressBarWidth-2; j++ {
			if i == 0 || i == ProgressBarWidth-2+2 {
				phase += pass
			} else if j == i-1 {
				phase += act
			} else {
				phase += pass
			}
		}
		frames = append(frames, phase)
	}
	return frames
}
func spinnerStyle() mpb.BarFillerBuilder {
	return mpb.BarFillerBuilderFunc(func() mpb.BarFiller {
		return mpb.SpinnerStyle(getSpinnerFrames()...).Build()
	})
}
