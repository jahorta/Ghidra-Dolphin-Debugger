package dolphingdbdebugger;

import java.awt.BorderLayout;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.swing.AbstractAction;
import javax.swing.Action;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.WindowPosition;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import dolphingdbdebugger.GDBMessages.GDBMessage;
import ghidra.app.services.DebuggerLogicalBreakpointService;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.app.services.ProgramManager;
import ghidra.debug.api.breakpoint.LogicalBreakpoint;
import ghidra.debug.api.breakpoint.LogicalBreakpointsChangeListener;
import ghidra.framework.Application;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFormatException;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.trace.database.DBTrace;
import ghidra.trace.model.breakpoint.TraceBreakpointKind;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import resources.Icons;

public class DolphinGDBComponentProvider extends ComponentProvider implements LogicalBreakpointsChangeListener {

		private JPanel panel;
        private JTextArea textArea;
        private JTextField commandField;
        private DockingAction settingsAction;
        private DockingAction connectAction;
        
        private String dolphinHost;
        private int dolphinPort;
        private DolphinGDBDebuggerModel model;
        private Thread asyncUiThread;
        private final AtomicBoolean asyncRunning = new AtomicBoolean(false);
        private DolphinGDBTraceManager traceManager;
        private PluginTool tool;
        
        private final List<String> commandHistory = new ArrayList<>();
        private int historyIndex = -1;

        private static final String OPTION_DOLPHIN_HOST = "Dolphin Host";
        private static final String OPTION_DOLPHIN_PORT = "Dolphin Port";
        private static final String DEFAULT_DOLPHIN_HOST = "localhost";
        private static final int DEFAULT_DOLPHIN_PORT = 2345;
        private static final int HISTORY_LIMIT = 100;
        
        

        public DolphinGDBComponentProvider(PluginTool tool, String name, String owner) {
        	super(tool, "Dolphin GDB Debugger", owner);
            setTitle("Dolphin GDB Debugger");
            setWindowMenuGroup("Debugger");
            setDefaultWindowPosition(WindowPosition.RIGHT);
            
            dolphinHost = loadDolphinHost();
            dolphinPort = loadDolphinPort();
            buildPanel();
            createActions();
            this.tool = tool;
            model = new DolphinGDBDebuggerModel(textArea);
            traceManager = new DolphinGDBTraceManager(tool);
            loadCommandHistoryFromFile();
            tool.getService(DebuggerLogicalBreakpointService.class).addChangeListener(this);
        }

        private void buildPanel() {
            panel = new JPanel(new BorderLayout());
            textArea = new JTextArea(10, 40);
            textArea.setEditable(false);
            panel.add(new JScrollPane(textArea), BorderLayout.CENTER);

            JPanel commandPanel = new JPanel(new BorderLayout());
            commandField = new JTextField();
            
            Action sendAction = new AbstractAction() 
            {
            	@Override
            	public void actionPerformed(ActionEvent e)
            	{
                    String command = commandField.getText().trim();
                    if (!command.isEmpty()) {
                        commandHistory.add(command);
                    	historyIndex = commandHistory.size(); // reset to end
                        if (commandHistory.size() >= HISTORY_LIMIT) {
                            commandHistory.remove(0);
                        } else {
                        	historyIndex += 1;
                        }
                        processCommand(command);
                    }
                    commandField.setText("");
            	}
            };
            
            commandField.addActionListener(sendAction);
            commandField.addKeyListener(new KeyAdapter() {
                @Override
                public void keyPressed(KeyEvent e) {
                    if (e.getKeyCode() == KeyEvent.VK_UP) {
                        if (historyIndex > 0) {
                            historyIndex--;
                            commandField.setText(commandHistory.get(historyIndex));
                        }
                        e.consume();
                    } else if (e.getKeyCode() == KeyEvent.VK_DOWN) {
                        if (historyIndex < commandHistory.size() - 1) {
                            historyIndex++;
                            commandField.setText(commandHistory.get(historyIndex));
                        } else {
                            historyIndex = commandHistory.size();
                            commandField.setText("");
                        }
                        e.consume();
                    }
                }
            });

            JButton sendButton = new JButton("Send");
            sendButton.addActionListener(sendAction);

            commandPanel.add(commandField, BorderLayout.CENTER);
            commandPanel.add(sendButton, BorderLayout.EAST);
            panel.add(commandPanel, BorderLayout.SOUTH);

            setVisible(true);
        }

        private void createActions() {
        	
            connectAction = new DockingAction("Connect to Dolphin", getName()) {
                @Override
                public void actionPerformed(ActionContext context) {
                	processCommand("connect");
                }
            };
            connectAction.setToolBarData(new ToolBarData(Icons.REFRESH_ICON, null));
            connectAction.setEnabled(true);
            connectAction.markHelpUnnecessary();
            dockingTool.addLocalAction(this, connectAction);

            settingsAction = new DockingAction("Configure", getName()) {
                @Override
                public void actionPerformed(ActionContext context) {
                    JTextField hostField = new JTextField(dolphinHost);
                    JTextField portField = new JTextField(Integer.toString(dolphinPort));

                    JPanel configPanel = new JPanel(new GridLayout(0, 1));
                    configPanel.add(new JLabel("Dolphin Host:"));
                    configPanel.add(hostField);
                    configPanel.add(new JLabel("Dolphin Port:"));
                    configPanel.add(portField);

                    int result = JOptionPane.showConfirmDialog(panel, configPanel, "Debugger Settings", JOptionPane.OK_CANCEL_OPTION);
                    if (result == JOptionPane.OK_OPTION) {
                        dolphinHost = hostField.getText().trim();
                        try {
                            dolphinPort = Integer.parseInt(portField.getText().trim());
                        } catch (NumberFormatException e) {
                            Msg.showError(getClass(), panel, "Invalid Port", "Please enter a valid number for the port.");
                            return;
                        }
                        saveSettings(dolphinHost, dolphinPort);
                        textArea.append("[Settings] Settings successfully saved.");
                    }
                }
            };
            settingsAction.setToolBarData(new ToolBarData(Icons.CONFIGURE_FILTER_ICON, null));
            settingsAction.setEnabled(true);
            settingsAction.markHelpUnnecessary();
            dockingTool.addLocalAction(this, settingsAction);
        }
        
        private void showHelp() {
            Map<String, String> commands = new LinkedHashMap<>();
            commands.put("connect", "Connect using saved host/port");
            commands.put("connect <host>:<port>", "Connect to a specific address");
            commands.put("disconnect", "Disconnect from Dolphin GDB");
            commands.put("continue", "Resume program execution");
            commands.put("step", "Step one instruction");
            commands.put("get-registers", "Dump general (r) registers");
            commands.put("get-registers-all", "Dump all available registers");
            commands.put("get-register <name>", "Show a specific register (e.g. r1)");
            commands.put("list-registers", "List all available register names");
            commands.put("get-stack", "Print a backtrace from the stack");
            commands.put("get-snapshot [name]", "Take a snapshot of registers and stack with optional name");
            commands.put("set-breakpoint <addr>", "Set a breakpoint at an address (e.g. 80003100)");
            commands.put("help", "Show this help message");

            textArea.append("[Commands]\n");
            for (Map.Entry<String, String> entry : commands.entrySet()) {
                textArea.append(String.format("  %-25s - %s%n", entry.getKey(), entry.getValue()));
            }
        }
        
        private void processCommand(String input) {
            String[] parts = input.split("\\s+");
            String command = parts[0].toLowerCase();
            String[] args = java.util.Arrays.copyOfRange(parts, 1, parts.length);

            try {
                switch (command) {
                    case "connect":
                        String host = dolphinHost;
                        int port = dolphinPort;

                        if (args.length == 1 && args[0].contains(":")) {
                            String[] hostPort = args[0].split(":");
                            if (hostPort.length == 2) {
                                host = hostPort[0];
                                try {
                                    port = Integer.parseInt(hostPort[1]);
                                } catch (NumberFormatException e) {
                                    textArea.append("[Error] Invalid port: " + hostPort[1] + "\n");
                                    break;
                                }
                            } else {
                                textArea.append("[Error] Invalid format. Use: connect <host>:<port>\n");
                                break;
                            }
                        }

                        model.connect(host, port);
                        textArea.append("[Connected to Dolphin at " + host + ":" + port + "]\n");
                        if (traceManager.getTrace() == null) {
                            traceManager.createTrace("Dolphin Trace");
                        }
                        traceManager.recordSnapshot("Connected", model);
                        startAsyncUiThread();
                        dolphinHost = host;
                        dolphinPort = port;
                        saveSettings(dolphinHost, dolphinPort);
                        syncEnabledBreakpointsToGDB();
                        break;
                    case "disconnect":
                    	if (!ensureConnected()) break;
                        model.disconnect();
                        textArea.append("[Disconnected from Dolphin]\n");
                        break;
                    case "continue":
                    	if (!ensureConnected()) break;
                        model.continueExecution();
                        textArea.append("[Sent: continue]\n");
                        break;
                    case "step":
                    	if (!ensureConnected()) break;
                        model.singleStep();
                        textArea.append("[Sent: step]\n");
                        break;
                    case "get-registers-all":
                        if (!ensureConnected()) break;
                        textArea.append("[All Registers]\n");
                        textArea.append(model.getAllAvailableRegisters());
                        break;
                    case "get-registers":
                        if (!ensureConnected()) break;
                        textArea.append("[GPR Registers]\n");
                        textArea.append(model.getGeneralRegisters());
                        break;
                    case "get-register":
                    	if (!ensureConnected()) break;
                        if (args.length < 1) {
                            textArea.append("[Error] Usage: get-register <name>\n");
                        } else {
                        	String regName = args[0];
                        	String result = model.getRegisterFormatted(regName);
                        	textArea.append(result + "\n");
                        }
                        break;
                    case "list-registers":
                    	if (!ensureConnected()) break;
                        String allRegs = String.join(", ", model.listRegisters());
                        textArea.append("[Registers] " + allRegs + "\n");
                        break;
                    case "get-stack":
                        if (!ensureConnected()) break;
                        List<String> trace = model.getStackTrace(16);
                        textArea.append("[Stack Trace]\n");
                        textArea.append(formatStackTrace(trace));
                        break;
                    case "get-snapshot":
                        if (!ensureConnected()) break;
                        String snapName = args.length > 0 ? String.join(" ", args) : "Snapshot";
                        traceManager.recordSnapshot(snapName, model);
                        break;
                    case "set-breakpoint":
                    	if (!ensureConnected()) break;
                        if (args.length < 1) {
                            textArea.append("[Error] Usage: set-breakpoint <hex-address>\n");
                        } else {
                            String addr = args[0];
                            Program program = tool.getService(ProgramManager.class).getCurrentProgram();
                            if (program != null) {
								try {
									Address address = program.getAddressFactory().getDefaultAddressSpace().getAddress(addr);
	                                DebuggerLogicalBreakpointService lbService = tool.getService(DebuggerLogicalBreakpointService.class);
	                                if (lbService != null) {
	                                	var kinds = List.of(TraceBreakpointKind.SW_EXECUTE);
	                                	lbService.placeBreakpointAt(program, address, 4, kinds, "Dolphin BP");
	                                    textArea.append("[Breakpoint] Set in Ghidra at 0x" + addr + "\n");
	                                } else {
	                                    textArea.append("[Warning] Could not access LogicalBreakpointService.\n");
	                                }
								} catch (AddressFormatException e) {
									e.printStackTrace();
								}
                            } else {
                                textArea.append("[Warning] No program loaded; could not create Ghidra breakpoint.\n");
                            }
                        }
                        break;
                    case "help":
                        showHelp();
                        break;
                    default:
                        textArea.append("[Error] Unknown command: " + command + " (use \"help\" to see available commands)\n");
                        break;
                }
            } catch (IOException ex) {
                textArea.append("[Exception] (" + command + ") " + ex.getMessage() + "\n");
                ex.printStackTrace();
            }
        }
        
        private Program getProgram() {
            ProgramManager pm = getTool().getService(ProgramManager.class);
            return (pm != null) ? pm.getCurrentProgram() : null;
        }
        
        private String formatStackTrace(List<String> trace) {
            if (trace == null || trace.isEmpty()) return "[Stack Trace] No entries.\n";

            StringBuilder out = new StringBuilder();
            Program program = getProgram();
            if (program == null) {
                out.append("[Warning] No program loaded.\n");
                for (String addr : trace) {
                    out.append("  at ").append(addr).append("\n");
                }
                return out.toString();
            }

            SymbolTable symbolTable = program.getSymbolTable();
            FunctionManager functionManager = program.getFunctionManager();

            for (String hexAddress : trace) {
                try {
                    long addressValue = Long.parseUnsignedLong(hexAddress.replace("0x", ""), 16);
                    Address address = program.getAddressFactory().getDefaultAddressSpace().getAddress(addressValue);

                    // Try to find the nearest function
                    Function function = functionManager.getFunctionContaining(address);
                    String funcName = function != null ? function.getName() : "<no function>";

                    // Try to find the closest symbol (could be label or function)
                    Symbol symbol = symbolTable.getPrimarySymbol(address);
                    String symbolName = symbol != null ? symbol.getName() : "<no symbol>";
                    Address base = symbol != null ? symbol.getAddress() : address;
                    long offset = address.subtract(base);

                    out.append(String.format("  %-20s (%s) %s+0x%X%n", funcName, hexAddress, symbolName, offset));
                } catch (Exception e) {
                    out.append("  at ").append(hexAddress).append(" [Error resolving address]\n");
                }
            }

            return out.toString();
        }
        
        private void startAsyncUiThread() {
            if (asyncUiThread != null && asyncUiThread.isAlive()) return;

            asyncRunning.set(true);
            asyncUiThread = new Thread(() -> {
                BlockingQueue<GDBMessage> queue = model.getExternalAsyncQueue();
                while (asyncRunning.get()) {
                    try {
                        GDBMessage msg = queue.take();
                        SwingUtilities.invokeLater(() -> {
                            handleAsyncMessage(msg);
                        });
                    } catch (InterruptedException ignored) {}
                }
            }, "Async-UI-Handler");
            asyncUiThread.start();
        }
        
        private void handleAsyncMessage(GDBMessage msg) {
            switch (msg.getType()) {
                case STOP_SIGNAL:
                	String formatted = formatStopMessage(msg.getRaw());
                    textArea.append("[Target Stopped] " + formatted + "\n");
                    break;
                case OUTPUT:
                    textArea.append("[Program Output] " + msg.getRaw().substring(1) + "\n"); // skip 'O'
                    break;
                case ERROR:
                    textArea.append("[Error] " + msg.getRaw() + "\n");
                    break;
                default:
                    textArea.append("[Async] " + msg.getRaw() + "\n");
                    break;
            }
        }
        
        public String formatStopMessage(String raw) {
            try {
                int signal = Integer.parseInt(raw.substring(1, 3), 16);
                Map<String, String> fields = new LinkedHashMap<>();

                String[] parts = raw.substring(3).split(";");
                for (String part : parts) {
                    int idx = part.indexOf(':');
                    if (idx > 0 && idx < part.length() - 1) {
                        String regIdHex = part.substring(0, idx);
                        String value = part.substring(idx + 1);
                        int regId = Integer.parseInt(regIdHex, 16);

                        String regName = DolphinGDBDebuggerModel.getRegisterNameById(regId);
                        if (regName == null) regName = "r" + regIdHex; // fallback

                        fields.put(regName, value);
                    }
                }

                StringBuilder sb = new StringBuilder();
                sb.append("Signal ").append(signal);
                if (fields.containsKey("pc")) {
                    sb.append(" @ PC=0x").append(fields.get("pc"));
                }
                if (fields.containsKey("r1")) {
                    sb.append(" : StackPtr=0x").append(fields.get("r1"));
                }

                return sb.toString();

            } catch (Exception e) {
                return "[Invalid stop message] " + raw;
            }
        }
        
        private boolean ensureConnected() {
            if (!model.isConnected()) {
                textArea.append("[Error] Not connected to Dolphin GDB.\n");
                return false;
            }
            return true;
        }

        @Override
        public JComponent getComponent() {
            return panel;
        }

        private String loadDolphinHost() {
            return getTool().getOptions("DolphinGDB").getString(OPTION_DOLPHIN_HOST, DEFAULT_DOLPHIN_HOST);
        }

        private int loadDolphinPort() {
            return getTool().getOptions("DolphinGDB").getInt(OPTION_DOLPHIN_PORT, DEFAULT_DOLPHIN_PORT);
        }

        private void saveSettings(String host, int port) {
            ToolOptions options = getTool().getOptions("DolphinGDB");
            options.setString(OPTION_DOLPHIN_HOST, host);
            options.setInt(OPTION_DOLPHIN_PORT, port);
        }
        
        public void saveAndCloseTrace() {
            DolphinGDBTraceManager manager = this.traceManager;
            if (manager != null && manager.getTrace() != null) {
                DBTrace trace = (DBTrace) manager.getTrace();
                if (trace.isChanged()) {
                    try {
                        trace.save("Auto-saved before program close", TaskMonitor.DUMMY);
                        Msg.info(this, "[TraceManager] Trace auto-saved on program close.");
                    } catch (CancelledException | IOException e) {
                        Msg.showError(this, null, "Failed to save trace", e.getMessage(), e);
                    }
                }
                DebuggerTraceManagerService tm = tool.getService(DebuggerTraceManagerService.class);
                if (tm != null) {
                    tm.closeTrace(trace);
                    Msg.info(this, "[TraceManager] Trace closed via DebuggerTraceManagerService.");
                }
            }
        }
        
        public void saveCommandHistoryToFile() {
            try {
            	File dir = new File(Application.getUserSettingsDirectory(), "DolphinGDBDebugger");
            	if (!dir.exists()) {
            	    dir.mkdirs();
            	}
            	File file = new File(dir, "command-history.txt");

                List<String> trimmed = commandHistory.size() > HISTORY_LIMIT
                    ? commandHistory.subList(commandHistory.size() - HISTORY_LIMIT, commandHistory.size())
                    : commandHistory;

            	Files.write(file.toPath(), trimmed, StandardCharsets.UTF_8);
            } catch (IOException e) {
                Msg.warn(this, "Failed to save command history: " + e.getMessage());
            }
        }
        
        public void loadCommandHistoryFromFile() {
            try {
                Path file = new File(new File(Application.getUserSettingsDirectory(), "DolphinGDBDebugger"), "command-history.txt").toPath();


                if (Files.exists(file)) {
                    List<String> lines = Files.readAllLines(file, StandardCharsets.UTF_8);
                    commandHistory.clear();
                    commandHistory.addAll(lines);
                    historyIndex = commandHistory.size();
                }
            } catch (IOException e) {
                Msg.warn(this, "Failed to load command history: " + e.getMessage());
            }
        }
        
        private void syncEnabledBreakpointsToGDB() {
            var lbService = tool.getService(DebuggerLogicalBreakpointService.class);
            if (lbService == null) {
                Msg.warn(this, "[Breakpoint Sync] DebuggerLogicalBreakpointService not found.");
                return;
            }
            textArea.append("[Logical Breakpoint] Syncing breakpoints with Dolphin");
            for (LogicalBreakpoint lb : lbService.getAllBreakpoints()) {
                if (!lb.computeState().isEnabled()) {
                    continue;
                }
                try {
                    breakpointAdded(lb);
                } catch (Exception e) {
                    Msg.showError(this, null, "Breakpoint Sync Failed", "Error syncing breakpoint: " + e.getMessage(), e);
                }
            }
        }
        
        @Override
        public void breakpointAdded(LogicalBreakpoint lb) {
            if (!ensureConnected()) return;
            if (!lb.computeState().isEnabled()) return;

            Address address = lb.getAddress();
            long addrVal = address.getOffset();
            try {
				model.setBreakpoint(addrVal);
				textArea.append("[Logical Breakpoint] Sent to GDB at 0x" + Long.toHexString(addrVal) + "\n");
			} catch (IOException e) {
				Msg.error(this, "[Logical Breakpoint] Failed to add breakpoint:" + e);
			}
            
        }

        @Override
        public void breakpointRemoved(LogicalBreakpoint lb) {
            if (!ensureConnected()) return;

            Address address = lb.getAddress();
            long addrVal = address.getOffset();
            try {
				model.removeBreakpoint(addrVal);
				textArea.append("[Logical Breakpoint] Removed from GDB at 0x" + Long.toHexString(addrVal) + "\n");
			} catch (IOException e) {
				Msg.error(this, "[Logical Breakpoint] Failed to remove breakpoint:" + e);
			}
            
        }
        
        @Override
        public void breakpointUpdated(LogicalBreakpoint lb) {
            if (!ensureConnected()) return;
            
            Msg.info(this, "Received breakpoint update. Forwarding to appropriate handler");
            
            if (lb.computeState().isEnabled()) {
            	breakpointAdded(lb);
            } else {
            	breakpointRemoved(lb);
            }
        }
    }