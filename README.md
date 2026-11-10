# Pulse

A calm, easy-to-read system monitor for Fedora / GNOME. Pulse tells you in plain language how your computer is doing and what is using it.

- **Summary**: one sentence at the top, like *"Everything's running smoothly"* or *"Memory is getting full: Firefox is using the most"*.
- **Cards**: Processor, Memory, Graphics (VRAM), Storage and Internet, each with a plain-language status (*Relaxed*, *Plenty free*, *Almost full*) and a live graph.
- **What's using it**: switch between memory, processor and graphics. Processes are grouped into the apps you know, with their real names and icons, so a browser's 20 helper processes show up as one entry. Background services get friendly names like *Sound & screen sharing* or *File search indexer*.
- **Graphics memory**: per-app VRAM on NVIDIA (via `nvidia-smi`) and AMD. If the dedicated GPU is asleep, Pulse leaves it asleep to save battery.
- **Ending things safely**:
  - Apps are asked to quit, with *Force End* if they don't respond.
  - Background services are stopped through systemd, so they don't just restart. Pulse also shows which other services keep a service running and can stop the whole chain.
  - Parts of the desktop that would log you out (GNOME Shell, the session, systemd…) are protected.
- **Crash-loop detection**: services that keep failing and restarting are flagged at the top, with a button to stop them.

## Requirements

Python 3, GTK 4, libadwaita ≥ 1.7, PyGObject and psutil. These are preinstalled on Fedora Workstation (`sudo dnf install python3-psutil` if psutil is missing).

## Run

```bash
./pulse.py
```

## Install to the app grid

```bash
ln -sf "$PWD/pulse.py" ~/.local/bin/pulse
install -Dm644 icons/hicolor/scalable/apps/io.github.samsyk.Pulse.svg ~/.local/share/icons/hicolor/scalable/apps/io.github.samsyk.Pulse.svg
sed "s|^Exec=.*|Exec=$PWD/pulse.py|" io.github.samsyk.Pulse.desktop > ~/.local/share/applications/io.github.samsyk.Pulse.desktop
```

## Layout

- `pulse.py`: everything. Data collection (`Collector`, `GpuReader`), app/service naming (`AppIndex`, `classify`), systemd helpers and the GTK4/libadwaita interface
- `icons/`: the app icon and the symbolic icons used on the cards
