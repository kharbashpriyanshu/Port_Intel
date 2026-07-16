# 🎬 PortIntel Demonstration GIF Script

This document provides a step-by-step recording script to create a 60-90 second GIF for the `README.md` using a terminal recorder like [Asciinema](https://asciinema.org/) or [Terminalizer](https://terminalizer.com/).

---

## Preparation
- Ensure `portintel` is installed (`pip install .`).
- Clear the terminal screen.
- Set terminal font to something modern (e.g., Fira Code, Hack) at a readable size.
- Ensure you have a live target to scan (e.g., `scanme.nmap.org` or a local vulnerable VM `192.168.1.150`).

## Script Timeline

### Segment 1: The Help Menu (0:00 - 0:10)
1. **Type:** `portintel help`
2. **Action:** Press Enter.
3. **Wait:** Pause for 3 seconds to let the viewer see the professional menu, commands, and examples.

### Segment 2: Host Discovery (0:10 - 0:25)
1. **Type:** `clear`
2. **Type:** `portintel discover --network 192.168.1.0/24`
3. **Action:** Press Enter.
4. **Visual:** The viewer sees the engine sweeping the network and identifying alive hosts.
5. **Wait:** Pause for 2 seconds on the "Discovery Complete" message.

### Segment 3: Intelligent Deep Scan (0:25 - 0:50)
1. **Type:** `clear`
2. **Type:** `portintel scan --target 192.168.1.150 --start 1 --end 1000 --vuln --export reports/scan.html`
3. **Action:** Press Enter.
4. **Visual:** 
   - Banner prints.
   - Scan initiates.
   - Wait ~10 seconds while it scans.
   - The Summary Table appears, complete with CPE identifiers, Risk Scores, and Extracted Versions.
   - The "[+] HTML report generated: reports/scan.html" message appears.
5. **Wait:** Pause for 4 seconds so the viewer can read the output.

### Segment 4: Viewing the Output (0:50 - 1:00)
1. **Type:** `cat reports/scan.html | head -n 20` (Or visually open the HTML in a quick browser split-screen if doing a video).
2. **Action:** If purely terminal, just show the file exists.
3. **Finish Recording.**

## Rendering
- Render the GIF with a framerate of ~15fps.
- Apply a dark theme (e.g., Dracula or One Dark) during rendering.
- Save as `docs/assets/demo.gif`.
