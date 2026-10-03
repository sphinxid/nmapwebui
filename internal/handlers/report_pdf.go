package handlers

import (
	"bytes"
	"fmt"
	"sort"
	"time"

	"github.com/go-pdf/fpdf"
	"nmapwebui/internal/models"
)

// Colours used by the PDF report (RGB).
var (
	pdfInk     = [3]int{17, 24, 39}    // near-black text
	pdfMuted   = [3]int{107, 114, 128} // secondary text
	pdfLine    = [3]int{229, 231, 235} // borders
	pdfFill    = [3]int{249, 250, 251} // alternating rows / cards
	pdfHead    = [3]int{243, 244, 246} // table header
	pdfGreen   = [3]int{5, 150, 105}
	pdfAmber   = [3]int{217, 119, 6}
	pdfRed     = [3]int{220, 38, 38}
	pdfBlue    = [3]int{37, 99, 235}
	pdfGrey    = [3]int{156, 163, 175}
	pdfGreenBg = [3]int{209, 250, 229}
	pdfAmberBg = [3]int{254, 243, 199}
	pdfRedBg   = [3]int{254, 226, 226}
	pdfGreyBg  = [3]int{243, 244, 246}
)

func stateColours(state string) (fg, bg [3]int) {
	switch state {
	case "open":
		return pdfGreen, pdfGreenBg
	case "filtered":
		return pdfAmber, pdfAmberBg
	case "closed":
		return pdfMuted, pdfGreyBg
	}
	return pdfMuted, pdfGreyBg
}

// renderPDFReport draws a scan report with the pure-Go fpdf library, so PDF
// export needs no external renderer such as wkhtmltopdf.
func renderPDFReport(report models.ScanReport) ([]byte, error) {
	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(14, 14, 14)
	pdf.SetAutoPageBreak(true, 18)
	tr := pdf.UnicodeTranslatorFromDescriptor("") // core fonts are cp1252; map UTF-8 safely
	pageW, _ := pdf.GetPageSize()
	left, _, right, _ := pdf.GetMargins()
	contentW := pageW - left - right

	taskName := ""
	if report.ScanRun != nil && report.ScanRun.Task.Name != "" {
		taskName = report.ScanRun.Task.Name
	}
	generated := time.Now().Format("2006-01-02 15:04 MST")

	pdf.SetFooterFunc(func() {
		pdf.SetY(-12)
		pdf.SetFont("Helvetica", "", 8)
		pdf.SetTextColor(pdfMuted[0], pdfMuted[1], pdfMuted[2])
		pdf.CellFormat(contentW/2, 5, tr(fmt.Sprintf("NmapWebUI · Report #%d", report.ID)), "", 0, "L", false, 0, "")
		pdf.CellFormat(contentW/2, 5, fmt.Sprintf("Page %d of {nb}", pdf.PageNo()), "", 0, "R", false, 0, "")
	})
	pdf.AliasNbPages("")
	pdf.AddPage()

	// ---- Title block -------------------------------------------------------
	pdf.SetFont("Helvetica", "B", 20)
	pdf.SetTextColor(pdfInk[0], pdfInk[1], pdfInk[2])
	pdf.CellFormat(contentW, 10, fmt.Sprintf("Scan Report #%d", report.ID), "", 1, "L", false, 0, "")
	pdf.SetFont("Helvetica", "", 10)
	pdf.SetTextColor(pdfMuted[0], pdfMuted[1], pdfMuted[2])
	meta := fmt.Sprintf("Generated %s", generated)
	if taskName != "" {
		meta = fmt.Sprintf("Task: %s  ·  Run #%d  ·  Scanned %s  ·  Exported %s",
			taskName, report.ScanRunID, report.CreatedAt.Format("2006-01-02 15:04"), generated)
	}
	pdf.CellFormat(contentW, 6, tr(meta), "", 1, "L", false, 0, "")
	if report.Summary != "" {
		pdf.MultiCell(contentW, 5, tr(report.Summary), "", "L", false)
	}
	pdf.Ln(3)
	pdf.SetDrawColor(pdfLine[0], pdfLine[1], pdfLine[2])
	pdf.Line(left, pdf.GetY(), left+contentW, pdf.GetY())
	pdf.Ln(5)

	// ---- Stats -------------------------------------------------------------
	hostsUp, openPorts := 0, 0
	services := map[string]bool{}
	for _, h := range report.Hosts {
		if h.Status == "up" {
			hostsUp++
		}
		for _, p := range h.Ports {
			if p.State == "open" {
				openPorts++
				if p.Service != "" {
					services[p.Service] = true
				}
			}
		}
	}
	stats := []struct {
		value  int
		label  string
		colour [3]int
	}{
		{len(report.Hosts), "HOSTS", pdfInk},
		{hostsUp, "HOSTS UP", pdfGreen},
		{openPorts, "OPEN PORTS", pdfAmber},
		{len(services), "SERVICES", pdfBlue},
	}
	gap := 4.0
	boxW := (contentW - gap*3) / 4
	y := pdf.GetY()
	for i, s := range stats {
		x := left + float64(i)*(boxW+gap)
		pdf.SetFillColor(pdfFill[0], pdfFill[1], pdfFill[2])
		pdf.SetDrawColor(pdfLine[0], pdfLine[1], pdfLine[2])
		pdf.RoundedRect(x, y, boxW, 20, 2, "1234", "FD")
		pdf.SetXY(x, y+3)
		pdf.SetFont("Helvetica", "B", 18)
		pdf.SetTextColor(s.colour[0], s.colour[1], s.colour[2])
		pdf.CellFormat(boxW, 9, fmt.Sprintf("%d", s.value), "", 2, "C", false, 0, "")
		pdf.SetFont("Helvetica", "", 7.5)
		pdf.SetTextColor(pdfMuted[0], pdfMuted[1], pdfMuted[2])
		pdf.CellFormat(boxW, 5, s.label, "", 0, "C", false, 0, "")
	}
	pdf.SetY(y + 20 + 8)

	// ---- Hosts -------------------------------------------------------------
	if len(report.Hosts) == 0 {
		pdf.SetFont("Helvetica", "I", 10)
		pdf.SetTextColor(pdfMuted[0], pdfMuted[1], pdfMuted[2])
		pdf.CellFormat(contentW, 8, "No hosts were found in this scan.", "", 1, "L", false, 0, "")
	}

	cols := []struct {
		title string
		w     float64
		align string
	}{
		{"PORT", 24, "L"}, {"STATE", 22, "L"}, {"SERVICE", 40, "L"}, {"VERSION", 0, "L"},
	}
	cols[3].w = contentW - cols[0].w - cols[1].w - cols[2].w

	drawTableHeader := func() {
		pdf.SetFont("Helvetica", "B", 7.5)
		pdf.SetTextColor(pdfMuted[0], pdfMuted[1], pdfMuted[2])
		pdf.SetFillColor(pdfHead[0], pdfHead[1], pdfHead[2])
		for _, c := range cols {
			pdf.CellFormat(c.w, 7, c.title, "", 0, c.align, true, 0, "")
		}
		pdf.Ln(-1)
	}

	hosts := append([]models.HostFinding(nil), report.Hosts...)
	sort.SliceStable(hosts, func(i, j int) bool { return hosts[i].IPAddress < hosts[j].IPAddress })

	for _, h := range hosts {
		ports := append([]models.PortFinding(nil), h.Ports...)
		sort.SliceStable(ports, func(i, j int) bool {
			if ports[i].PortNumber != ports[j].PortNumber {
				return ports[i].PortNumber < ports[j].PortNumber
			}
			return ports[i].Protocol < ports[j].Protocol
		})
		openCount := 0
		for _, p := range ports {
			if p.State == "open" {
				openCount++
			}
		}

		// Keep the host header together with at least the table header and one row.
		if _, pageH := pdf.GetPageSize(); pdf.GetY()+30 > pageH-18 {
			pdf.AddPage()
		}

		// Host header bar
		y := pdf.GetY()
		pdf.SetFillColor(pdfFill[0], pdfFill[1], pdfFill[2])
		pdf.SetDrawColor(pdfLine[0], pdfLine[1], pdfLine[2])
		pdf.Rect(left, y, contentW, 12, "FD")
		statusFg, statusBg := pdfRed, pdfRedBg
		if h.Status == "up" {
			statusFg, statusBg = pdfGreen, pdfGreenBg
		}
		// status pill
		pdf.SetFillColor(statusBg[0], statusBg[1], statusBg[2])
		pdf.RoundedRect(left+3, y+3.5, 12, 5, 2.5, "1234", "F")
		pdf.SetFont("Helvetica", "B", 7)
		pdf.SetTextColor(statusFg[0], statusFg[1], statusFg[2])
		pdf.SetXY(left+3, y+3.5)
		pdf.CellFormat(12, 5, tr(h.Status), "", 0, "C", false, 0, "")
		// ip + hostname
		pdf.SetXY(left+18, y+2)
		pdf.SetFont("Courier", "B", 11)
		pdf.SetTextColor(pdfInk[0], pdfInk[1], pdfInk[2])
		pdf.CellFormat(pdf.GetStringWidth(h.IPAddress)+2, 8, tr(h.IPAddress), "", 0, "L", false, 0, "")
		if h.Hostname != "" {
			pdf.SetFont("Helvetica", "", 9)
			pdf.SetTextColor(pdfMuted[0], pdfMuted[1], pdfMuted[2])
			pdf.CellFormat(0, 8, tr(h.Hostname), "", 0, "L", false, 0, "")
		}
		// right side: open ports + OS
		rightText := fmt.Sprintf("%d open port%s", openCount, plural(openCount))
		if h.OSInfo != "" {
			rightText = truncateToWidth(pdf, tr(h.OSInfo), 70) + "  ·  " + rightText
		}
		pdf.SetFont("Helvetica", "", 8)
		pdf.SetTextColor(pdfMuted[0], pdfMuted[1], pdfMuted[2])
		pdf.SetXY(left, y+2)
		pdf.CellFormat(contentW-3, 8, rightText, "", 0, "R", false, 0, "")
		pdf.SetXY(left, y+12)

		if len(ports) == 0 {
			pdf.SetFont("Helvetica", "I", 8.5)
			pdf.SetTextColor(pdfMuted[0], pdfMuted[1], pdfMuted[2])
			pdf.CellFormat(contentW, 8, "No port information for this host.", "", 1, "L", false, 0, "")
			pdf.Ln(4)
			continue
		}

		drawTableHeader()
		for i, p := range ports {
			if _, pageH := pdf.GetPageSize(); pdf.GetY()+7 > pageH-18 {
				pdf.AddPage()
				drawTableHeader()
			}
			fill := i%2 == 1
			pdf.SetFillColor(pdfFill[0], pdfFill[1], pdfFill[2])
			rowY := pdf.GetY()

			pdf.SetFont("Courier", "B", 8.5)
			pdf.SetTextColor(pdfInk[0], pdfInk[1], pdfInk[2])
			pdf.CellFormat(cols[0].w, 7, fmt.Sprintf("%d/%s", p.PortNumber, p.Protocol), "", 0, "L", fill, 0, "")

			// state pill inside its cell
			fg, bg := stateColours(p.State)
			x := pdf.GetX()
			pdf.CellFormat(cols[1].w, 7, "", "", 0, "L", fill, 0, "")
			pdf.SetFillColor(bg[0], bg[1], bg[2])
			pillW := pdf.GetStringWidth(p.State) + 4
			pdf.RoundedRect(x+1, rowY+1.5, pillW, 4, 2, "1234", "F")
			pdf.SetXY(x+1, rowY+1.5)
			pdf.SetFont("Helvetica", "B", 6.5)
			pdf.SetTextColor(fg[0], fg[1], fg[2])
			pdf.CellFormat(pillW, 4, tr(p.State), "", 0, "C", false, 0, "")
			pdf.SetXY(x+cols[1].w, rowY)
			pdf.SetFillColor(pdfFill[0], pdfFill[1], pdfFill[2])

			pdf.SetFont("Helvetica", "", 8.5)
			pdf.SetTextColor(pdfInk[0], pdfInk[1], pdfInk[2])
			pdf.CellFormat(cols[2].w, 7, truncateToWidth(pdf, tr(orDash(p.Service)), cols[2].w-2), "", 0, "L", fill, 0, "")
			pdf.SetTextColor(pdfMuted[0], pdfMuted[1], pdfMuted[2])
			pdf.CellFormat(cols[3].w, 7, truncateToWidth(pdf, tr(orDash(p.Version)), cols[3].w-2), "", 0, "L", fill, 0, "")
			pdf.Ln(-1)
		}
		pdf.SetDrawColor(pdfLine[0], pdfLine[1], pdfLine[2])
		pdf.Line(left, pdf.GetY(), left+contentW, pdf.GetY())
		pdf.Ln(6)
	}

	var buf bytes.Buffer
	if err := pdf.Output(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// truncateToWidth shortens s with an ellipsis so it fits in w millimetres at
// the current font.
func truncateToWidth(pdf *fpdf.Fpdf, s string, w float64) string {
	if pdf.GetStringWidth(s) <= w {
		return s
	}
	r := []rune(s)
	for len(r) > 1 {
		r = r[:len(r)-1]
		if pdf.GetStringWidth(string(r)+"...") <= w {
			return string(r) + "..."
		}
	}
	return "..."
}
