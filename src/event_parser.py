import xml.etree.ElementTree as ET
import pandas as pd
from pathlib import Path

# Namespace used in Sysmon XML
NS = {"ev": "http://schemas.microsoft.com/win/2004/08/events/event"}

# Simple English descriptions for common Sysmon Event IDs
EVENT_DESCRIPTIONS = {
    "1": "Process created (a program started)",
    "2": "A process changed a file creation time",
    "3": "Network connection created",
    "4": "Sysmon service state changed",
    "5": "Process terminated (a program ended)",
    "6": "Driver loaded",
    "7": "Image (EXE/DLL) loaded",
    "8": "Remote thread created in another process",
    "9": "Raw disk access",
    "10": "Process accessed another process",
    "11": "File created on disk",
    "12": "Registry object created or deleted",
    "13": "Registry value set",
    "14": "Registry key/values renamed",
    "15": "File stream created",
    "22": "DNS query performed",
    "255": "Sysmon configuration change",
}

def load_sysmon_events(xml_path: str):
    """Load Event elements from Sysmon XML file."""
    tree = ET.parse(xml_path)
    root = tree.getroot()
    events = root.findall(".//ev:Event", NS)
    print(f"Loaded {len(events)} events from {xml_path}")
    return events

def parse_event(ev: ET.Element) -> dict:
    """Extract key fields from a single Sysmon <Event> element."""
    system = ev.find("ev:System", NS)
    data   = ev.find("ev:EventData", NS)

    event_id = system.find("ev:EventID", NS).text if system is not None else None
    computer = system.find("ev:Computer", NS).text if system is not None else None

    utc_time = None
    image    = None
    proc_id  = None

    if data is not None:
        for d in data.findall("ev:Data", NS):
            name = d.get("Name")
            if name == "UtcTime":
                utc_time = d.text
            elif name == "Image":
                image = d.text
            elif name == "ProcessId":
                proc_id = d.text

    description = EVENT_DESCRIPTIONS.get(event_id, "Other Sysmon event")

    return {
        "event_id": event_id,
        "description": description,
        "utc_time": utc_time,
        "image": image,
        "process_id": proc_id,
        "computer": computer,
    }

def to_sentence(row) -> str:
    """Turn one parsed event (DataFrame row) into a human‑readable sentence."""
    return (
        f"At {row.get('utc_time')}, on computer {row.get('computer')}, "
        f"{row.get('description')}: {row.get('image')} "
        f"(process ID {row.get('process_id')})."
    )

if __name__ == "__main__":
    xml_path = "data/sysmon_events.xml"

    # 1) Load and parse all events
    events = load_sysmon_events(xml_path)
    parsed = [parse_event(e) for e in events]

    # 2) Create DataFrame for analysis
    df = pd.DataFrame(parsed)

    # 3) Show top event types in plain language
    counts = (
        df.groupby(["event_id", "description"])
          .size()
          .reset_index(name="count")
          .sort_values("count", ascending=False)
    )
    print("\nTop Sysmon event types:")
    print(counts.head(10))

    # 4) Show a few example events as sentences
    print("\nSample human‑readable events:")
    for _, r in df.head(5).iterrows():
        print("- " + to_sentence(r))

    # 5) Highlight interesting events (simple heuristic)
    suspicious_images = [
        "cmd.exe",
        "powershell.exe",
        "pwsh.exe",
        "wmic.exe",
        "rundll32.exe",
        "regsvr32.exe",
    ]

    interesting = df[
        df["image"].notna()
        & df["image"].str.lower().str.contains(
            "|".join(x.lower() for x in suspicious_images),
            na=False,
        )
    ]

    print("\nInteresting events (potentially higher priority):")
    print(
        interesting[["utc_time", "description", "image", "process_id"]]
        .head(20)
        .to_string(index=False)
    )

    print("\nInteresting events as sentences:")
    for _, r in interesting.head(20).iterrows():
        print("- " + to_sentence(r))

    # 6) Save full human-readable report
    output_dir = Path("output")
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "sysmon_report.txt"

    all_sentences = [to_sentence(r) for _, r in df.iterrows()]

    with output_path.open("w", encoding="utf-8") as f:
        f.write("Sysmon Human-Readable Report\n")
        f.write("=" * 40 + "\n\n")

        f.write("Top event types:\n")
        f.write(counts.to_string(index=False))
        f.write("\n\nInteresting / potentially suspicious events:\n")
        for _, r in interesting.iterrows():
            f.write("- " + to_sentence(r) + "\n")

        f.write("\nAll events (full log in sentences):\n")
        for line in all_sentences:
            f.write("- " + line + "\n")

    print(f"\nReport saved to {output_path}")
