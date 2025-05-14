package dolphindebugger.GDB;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.swing.JTextArea;

import dolphindebugger.GDB.Messages.GDBMessage;
import dolphindebugger.GDB.Messages.GDBMessageType;
import ghidra.util.Msg;

public class DolphinGDBDebuggerModel {

    private final GDBRSPClient rspClient;
    private final BlockingQueue<GDBMessage> responseQueue;
    private final BlockingQueue<GDBMessage> asyncQueue;
    private final BlockingQueue<GDBMessage> externalAsyncQueue;
    private Thread readerThread;
    private Thread asyncHandlerThread;
    private final AtomicBoolean running = new AtomicBoolean(false);
    private JTextArea outputArea;
    
    private static final String LOG_NAME = "GDB Debugger";
    private static final Map<String, Integer> REGISTER_ID_MAP = buildRegisterMap();
    private static final int MAX_MEM_BLOCK_SIZE = 0x1000;

    private static Map<String, Integer> buildRegisterMap() {
        Map<String, Integer> map = new java.util.HashMap<>();

        // GPRs r0-r31
        for (int i = 0; i < 32; i++) {
            map.put("r" + i, i);
        }

        // FPRs f0-f31 (IDs 32-63)
        for (int i = 0; i < 32; i++) {
            map.put("f" + i, 32 + i);
        }

        // Other named registers
        map.putAll(Map.ofEntries(
            Map.entry("pc", 64), Map.entry("msr", 65), Map.entry("cr", 66), Map.entry("lr", 67),
            Map.entry("ctr", 68), Map.entry("xer", 69), Map.entry("fpscr", 70), Map.entry("pvr", 87),
            Map.entry("sdr", 104), Map.entry("asr", 105), Map.entry("dar", 106), Map.entry("dsisr", 107),
            Map.entry("sprg0", 108), Map.entry("sprg1", 109), Map.entry("sprg2", 110), Map.entry("sprg3", 111),
            Map.entry("srr0", 112), Map.entry("srr1", 113), Map.entry("tl", 114), Map.entry("tu", 115),
            Map.entry("dec", 116), Map.entry("dabr", 117), Map.entry("ear", 118), Map.entry("hid0", 119),
            Map.entry("hid1", 120), Map.entry("iabr", 121), Map.entry("dabr2", 122), Map.entry("ummcr0", 124),
            Map.entry("upmc1", 125), Map.entry("upmc2", 126), Map.entry("usia", 127), Map.entry("ummcr1", 128),
            Map.entry("upmc3", 129), Map.entry("upmc4", 130), Map.entry("mmcr0", 131), Map.entry("pmc1", 132),
            Map.entry("pmc2", 133), Map.entry("sia", 134), Map.entry("mmcr1", 135), Map.entry("pmc3", 136),
            Map.entry("pmc4", 137), Map.entry("l2cr", 138), Map.entry("ictc", 139), Map.entry("thrm1", 140),
            Map.entry("thrm2", 141), Map.entry("thrm3", 142)
        ));

        return map;
    }
    
    public DolphinGDBDebuggerModel(JTextArea outputArea) {
    	this.outputArea = outputArea;
        this.rspClient = new GDBRSPClient();
        this.responseQueue = new LinkedBlockingQueue<>();
        this.asyncQueue = new LinkedBlockingQueue<>();
        this.externalAsyncQueue = new LinkedBlockingQueue<>();
    }

    public void connect(String host, int port) throws IOException {
        rspClient.connect(host, port);
        startListenerThread();
        startAsyncHandlerThread();
        
        // Send initial packet to keep Dolphin's GDB stub happy
        queryStopReason();
    }
    
    public BlockingQueue<GDBMessage> getExternalAsyncQueue() {
        return externalAsyncQueue;
    }

    public void disconnect() throws IOException {
        stopListenerThread();
        stopAsyncHandlerThread();
        rspClient.close();
    }
    
    public boolean isConnected() {
        return rspClient.isConnected();
    }

    private void startListenerThread() {
        running.set(true);
        readerThread = new Thread(() -> {
            try {
                while (running.get()) {
                    String packet = rspClient.readPacket();
                    if (packet != null) {
                        GDBMessage msg = GDBMessage.classify(packet);
                        switch (msg.getType()) {
                            case RESPONSE:
                            case ERROR:
                                responseQueue.offer(msg);
                                break;
                            default:
                                asyncQueue.offer(msg);
                                break;
                        }
                    }
                }
            } catch (IOException e) {
                if (running.get()) {
                    Msg.error(this, "[" + LOG_NAME + "]Reader thread error: " + e.getMessage());
                }
            }
        }, "GDB-RSP-Listener");
        readerThread.start();
    }

    private void stopListenerThread() {
        running.set(false);
        if (readerThread != null) {
            readerThread.interrupt();
            try {
                readerThread.join();
            } catch (InterruptedException ignored) {}
        }
    }
    
    private void startAsyncHandlerThread() {
        asyncHandlerThread = new Thread(() -> {
            try {
                while (running.get()) {
                    GDBMessage msg = asyncQueue.take();
                    handleAsyncMessage(msg);
                }
            } catch (InterruptedException ignored) {}
        }, "GDB-Async-Handler");
        asyncHandlerThread.start();
    }

    private void stopAsyncHandlerThread() {
        if (asyncHandlerThread != null) {
            asyncHandlerThread.interrupt();
            try {
                asyncHandlerThread.join();
            } catch (InterruptedException ignored) {}
        }
    }
    
    private void handleAsyncMessage(GDBMessage msg) {
        // Placeholder for async message handling logic
    	Msg.debug(this, "[" + LOG_NAME + "] Async Message Recieved: [" + msg.getType() + "] " + msg.getRaw());
    	if (msg.getType() == GDBMessageType.UNKNOWN) {
    		outputArea.append("[Async] [Unknown Type]" + msg.getRaw() + "\n");
    	} else {
    		externalAsyncQueue.offer(msg);
    	}
    }
    
    public synchronized GDBMessage sendCommand(String command) throws IOException {
        return sendCommand(command, true);
    }

    public synchronized GDBMessage sendCommand(String command, boolean awaitResponse) throws IOException {
        rspClient.sendPacket(command);
        Msg.debug(this, "[" + LOG_NAME + "] Command sent: " + command);
        
        if (!awaitResponse) {
            return new GDBMessage("SENT", GDBMessageType.ASYNC);
        }

        try {
            // Wait up to 1 second for a reply (you can adjust timeout as needed)
            GDBMessage msg = responseQueue.poll(2, TimeUnit.SECONDS);
            if (msg == null) {
                throw new IOException("Timeout waiting for GDB response");
            }

            Msg.debug(this, "[" + LOG_NAME + "] Message Recieved: [" + msg.getType() + "] " + msg.getRaw());
            return msg;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted while waiting for GDB stub response", e);
        }
    }

    // Example command helpers
    public void queryStopReason() {
        try {
			sendCommand("?", false);
		} catch (IOException e) {
			// This should never happen since we are not waiting for a response
			Msg.error(this, "[" + LOG_NAME + "] Got a response error from query stop reason. This should not happen." + e);
		}
    }

    public Set<String> listRegisters() {
        return REGISTER_ID_MAP.keySet();
    }
    
    public String getRegisterFormatted(String name) throws IOException {
        Integer id = REGISTER_ID_MAP.get(name.toLowerCase());
        if (id == null) {
            return "[Error] Unknown register: " + name;
        }
        GDBMessage msg = readRegister(id);
        return name + " = 0x" + msg.getRaw();
    }

    public GDBMessage readRegister(int id) throws IOException {
    	return sendCommand(String.format("p%X", id));
    }
    
    public String getGeneralRegisters() throws IOException {
        GDBMessage gprMsg = readRegisters();
        String gprData = gprMsg.getRaw();

        StringBuilder result = new StringBuilder();
        for (int i = 0; i < 32; i++) {
            String name = getRegisterNameById(i);
            String hex = gprData.substring(i * 8, i * 8 + 8);
            result.append(String.format("%-6s: 0x%s%n", name, hex));
        }
        return result.toString();
    }
    
    public String getAllAvailableRegisters() throws IOException {
        StringBuilder result = new StringBuilder();

        // 1. Fetch and format GPRs using `g`
        GDBMessage gprMsg = readRegisters();
        String gprData = gprMsg.getRaw();

        for (int id = 0; id < 32; id++) {
            String name = getRegisterNameById(id);
            String hex = gprData.substring(id * 8, id * 8 + 8);
            result.append(String.format("%-6s: 0x%s%n", name, hex));
        }

        // 2. Fetch and format FPRs using `p`
        for (int id = 32; id <= 63; id++) {
            String name = getRegisterNameById(id);
            GDBMessage msg = readRegister(id);
            result.append(String.format("%-6s: 0x%s%n", name, msg.getRaw()));
        }

        // 3. Fetch other specific registers (e.g. pc, lr, ctr, cr, etc.)
        int[] extras = {64, 67, 68, 69, 70}; // PC, LR, CTR, XER, FPSCR
        for (int id : extras) {
            String name = getRegisterNameById(id);
            GDBMessage msg = readRegister(id);
            result.append(String.format("%-6s: 0x%s%n", name, msg.getRaw()));
        }

        return result.toString();
    }
    
    public static String getRegisterNameById(int id) {
        for (Map.Entry<String, Integer> entry : REGISTER_ID_MAP.entrySet()) {
            if (entry.getValue() == id) return entry.getKey();
        }
        return "reg" + id;
    }
    
    public Map<String, Integer> getRegisterIdMap() {
        return REGISTER_ID_MAP;
    }

    public GDBMessage readRegisters() throws IOException {
        return sendCommand("g");
    }

    public GDBMessage readMemory(long address, int length) throws IOException {
    	int fullBlocks = length / MAX_MEM_BLOCK_SIZE;
    	int lastBlockLen = length % MAX_MEM_BLOCK_SIZE;
    	
    	StringBuilder allMessages = new StringBuilder();
    	long curAddr = address;
    	for (int i = 0; i < fullBlocks; i++) {
    		curAddr = address + (i * MAX_MEM_BLOCK_SIZE);
    		allMessages.append(sendCommand(String.format("m%x,%x", curAddr, MAX_MEM_BLOCK_SIZE)).getRaw());
    	}
    	allMessages.append(sendCommand(String.format("m%x,%x", curAddr, lastBlockLen)).getRaw());
        return sendCommand(String.format("m%x,%x", address, length));
    }
    
    public void setBreakpoint(long address) {
        try {
			sendCommand(String.format("Z0,%x,4", address));
		} catch (IOException e) {
			// This should never happen since we are not waiting for a response
			Msg.error(this, "[" + LOG_NAME + "] Got a response error from set breakpoint. This should not happen." + e);
		} // Assuming 4-byte instruction
    }
    
    public void removeBreakpoint(long address) {
    	try {
			sendCommand(String.format("z0,%x,4", address));
		} catch (IOException e) {
			// This should never happen since we are not waiting for a response
			Msg.error(this, "[" + LOG_NAME + "] Got a response error from remove breakpoint. This should not happen." + e);
		} // Assuming 4-byte instruction
    }

    public void continueExecution() {
        try {
			sendCommand("c", false);
		} catch (IOException e) {
			// This should never happen since we are not waiting for a response
			Msg.error(this, "[" + LOG_NAME + "] Got a response error from continue. This should not happen." + e);
		}
    }

    public void singleStep() {
        try {
			sendCommand("s", false);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    }
    
    public List<String> getStackTrace(int maxDepth) throws IOException {
        List<String> stackFxns = new ArrayList<>();

        // 1. Add the current PC (Program Counter) first
        String pcHex = getRegisterFormatted("pc").split("0x")[1];
        long pc = Long.parseUnsignedLong(pcHex, 16);
        stackFxns.add(String.format("0x%08X", pc));
        
        String spHex = getRegisterFormatted("r1").split("0x")[1];
        long sp = Long.parseUnsignedLong(spHex, 16);

        for (int i = 0; i < maxDepth && sp != 0; i++) {
            GDBMessage mem = readMemory(sp, 8); // back chain + return address
            String raw = mem.getRaw();
            if (raw.length() < 16) break;

            long nextSp = Long.parseUnsignedLong(raw.substring(0, 8), 16);
            long returnAddr = Long.parseUnsignedLong(raw.substring(8, 16), 16);

            if (nextSp == sp || nextSp == 0) break;
            stackFxns.add(String.format("0x%08X", returnAddr));
            sp = nextSp;
        }

        return stackFxns;
    }
    
    /**
     * Clear any pending messages in the queue (optional utility).
     */
    public void clearResponseQueue() {
        responseQueue.clear();
    }
}