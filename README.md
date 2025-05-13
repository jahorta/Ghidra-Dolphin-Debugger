# Ghidra Dolphin Debugger
A debugger for Dolphin Emulator in [Ghidra](https://github.com/NationalSecurityAgency/ghidra).

Connects to the GDB stub exposed by Dolphin Emulator to provide emulator state information to Ghidra.

## Features
- Connects to the GDB stub exposed by Dolphin Emulator
- Add and remove breakpoints using Ghidra's interface
- Continue or Step emulation
- Take snapshot of emulator state
    - Stack Frames
    - Register values
    - Memory state

## Requirements
- [Dolphin Emulator](https://dolphin-emu.org/)
- [Ghidra](https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_11.2.1_build)
- Java JDK 23
- Gradle 8.14
    
## Building
- Tested using Gradle v.8.14 with the GhidraDev extension in Eclipse

## Installation
- Copy the zip file to ``<Ghidra install directory>/Extensions/Ghidra``.
- Start Ghidra and use the "Install Extensions" dialog to finish the installation (``File -> Install Extensions...``)

## Usage
First, the Dolphin GDB stub needs to be active:
- Locate the configuration file for DolphinIn the configuration file:
    - Using portable.txt (recommended): ``<Dolphin Base Directory>/User/Config/Dolphin.ini``
    - Without portable.txt: ``<Documents folder>/Dolphin/Config/Dolphin.ini``
- Add socket/port information to the configuration file. In the [General] section add:
    - Windows:``GDBPort: <port>`` (host address is localhost by default)
    - Other:``GDBSocket: <hostAddress>:<port>``

Now the Dolphin GDB stub should be active when Dolphin runs a game. On starting a game, the game should pause immediately and expose the GDB stub for connection. 

Next in Ghidra, activate Ghidra's debugger tool and load your project. The Dolphin Debugger can be found . , enter ``connect`` to connect to the Dolphin GDB stub. Once connected, in the console of the tool you should see information about the current state of dolphin emulator. Breakpoints can be set in Ghidra and will be sent to the emulator.

# Custom Dolphin Emulator Build Recommended
It is recommended that you build Dolphin Emulator from source. The GDB stub is currently configured to check for requests once every 100000 CPU cycles. This is very rapid and may lead to FPS issues when running a game. Adding two zeros onto the end results in a responsive GDB stub without losing game performance. This can be found in: `dolphin\Source\Core\Core\PowerPC\GDBStub.cpp` and the variable to change is `GDB_UPDATE_CYCLES`.