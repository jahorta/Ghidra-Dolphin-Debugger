package dolphindebugger;

import ghidra.app.services.DebuggerStaticMappingService;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.app.services.ProgramManager;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFormatException;
import ghidra.program.model.address.AddressRangeImpl;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.trace.database.DBTrace;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.Trace;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.time.TraceSnapshot;
import ghidra.trace.model.memory.TraceMemoryFlag;
import ghidra.trace.model.memory.TraceMemorySpace;
import ghidra.trace.model.memory.TraceOverlappedRegionException;
import ghidra.trace.model.modules.TraceStaticMapping;
import ghidra.trace.model.modules.TraceStaticMappingManager;
import ghidra.trace.model.stack.TraceStack;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URL;
import java.nio.ByteBuffer;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import dolphindebugger.GDB.Messages.GDBMessage;
import dolphindebugger.GDB.DolphinGDBDebuggerModel;

public class DolphinTraceManager {
	
    private final PluginTool tool;

    private Trace trace;
    private TraceThread thread;
    private TraceSnapshot snapshot;
    private DolphinGDBDebuggerModel model;
    private List<MemoryBlock> programMemoryBlocks = null;

    public DolphinTraceManager(PluginTool tool, DolphinGDBDebuggerModel model) {
        this.tool = tool;
        this.model = model;
    }
    
    public void initializeProgramMemoryBlocks() {
        ProgramManager programManager = tool.getService(ProgramManager.class);
        if (programManager == null) {
            Msg.error(this, "ProgramManager service not available.");
            return;
        }

        Program program = programManager.getCurrentProgram();
        if (program == null) {
            Msg.error(this, "No program loaded in ProgramManager.");
            return;
        }

        programMemoryBlocks = new ArrayList<>();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            long start = block.getStart().getOffset();
            long end = block.getEnd().getOffset();
            if (start >= 0x80000000L && end <= 0x81FFFFFFL) {
                programMemoryBlocks.add(block);
            }
        }
        Msg.info(this, "Initialized " + programMemoryBlocks.size() + " memory blocks from loaded program.");
    }

    public void createTrace(String name) {
        initializeProgramMemoryBlocks();
        try {
            // Get the current program to use its language/compilerspec
            ProgramManager pm = tool.getService(ProgramManager.class);
            Program currentProgram = pm != null ? pm.getCurrentProgram() : null;
            if (currentProgram == null) {
                Msg.showError(this, null, "Trace Error", "No program loaded to get language and compiler spec.");
                return;
            }
            
            // Create thread
            CompilerSpec compilerSpec = currentProgram.getCompilerSpec();
            
            String timestamp = new SimpleDateFormat("yyyyMMdd_HHmmss").format(new Date());
            String fullName = name.replaceAll("\\s+", "_") + "_" + timestamp;

            trace = new DBTrace(fullName, compilerSpec, this);
            trace.setName(fullName);
                       
            DomainFolder root = tool.getProject().getProjectData().getRootFolder();
            DomainFile file = root.createFile(fullName, trace, TaskMonitor.DUMMY); // ✅ Makes it writable
            file.save(TaskMonitor.DUMMY); // ✅ Save once to ensure it's persisted

            // Activate the trace in the debugger UI
            DebuggerTraceManagerService traceManager = tool.getService(DebuggerTraceManagerService.class);
            if (traceManager != null) {
            	traceManager.openTrace(trace);
                traceManager.activateTrace(trace);
            }
            
            DebuggerStaticMappingService mappingService = tool.getService(DebuggerStaticMappingService.class);
            if (currentProgram != null && mappingService != null) {
                AddressSpace space = trace.getBaseAddressFactory().getDefaultAddressSpace();
                Address traceBase = space.getAddress(0x80000000L);  // Adjust as needed

                TraceStaticMappingManager mapManager = trace.getStaticMappingManager();
                
                boolean exists = false;
                URL programURL = currentProgram.getDomainFile().getLocalProjectURL(null);
                for (TraceStaticMapping m : mapManager.getAllEntries()) {
                    Address min = m.getMinTraceAddress();
                    URL mappedURL = m.getStaticProgramURL();

                    if (min.equals(traceBase) && programURL.equals(mappedURL)) {
                        exists = true;
                        break;
                    }
                }

                if (!exists) {
                	Memory memory = currentProgram.getMemory();

                	Address min = null;
                	Address max = null;

                	for (MemoryBlock block : memory.getBlocks()) {
                	    String blockName = block.getName().toLowerCase();
                	    if (blockName.contains("text")) {
                	        Address start = block.getStart();
                	        Address end = block.getEnd();

                	        if (min == null || start.compareTo(min) < 0) {
                	            min = start;
                	        }
                	        if (max == null || end.compareTo(max) > 0) {
                	            max = end;
                	        }
                	    }
                	}
                	AddressRange range;
                	if (min != null && max != null) {
                	    range = new AddressRangeImpl(min, max);
                	} else {
                	    // fallback if no text blocks found at all
                	    min = memory.getMinAddress();
                	    max = memory.getMaxAddress();
                	    range = new AddressRangeImpl(min, max);
                	}
                	Lifespan lifespan = Lifespan.span(0, Long.MAX_VALUE);
                	runInTransaction("Add Mapping", () -> {
                	    mapManager.add(range, lifespan, programURL, range.getMinAddress().toString());
                	});
                    Msg.info(this, "[TraceManager] Mapping created between trace and program");
                } else {
                    Msg.info(this, "[TraceManager] Mapping already exists.");
                }
            }

            Msg.info(this, "[TraceManager] Trace created and activated: " + fullName);
        } catch (Exception e) {
            Msg.showError(this, null, "Trace Error", "Failed to create trace: " + e.getMessage(), e);
        }
    }

    public void activateTrace() {
        DebuggerTraceManagerService traceManager = tool.getService(DebuggerTraceManagerService.class);
        if (traceManager != null && trace != null) {
            traceManager.openTrace(trace);
            traceManager.activateTrace(trace);
        }
    }
    
    public void runInTransaction(String label, Runnable work) {
        int tx = trace.startTransaction(label);
        try {
            work.run();
        } finally {
            trace.endTransaction(tx, true);
        }
    }
    
    public void recordSnapshot(String name) {
        if (trace == null) {
            Msg.showError(this, null, "Trace Error", "No trace has been created yet.");
            return;
        }
        
        Msg.info(this, "Starting Snapshot '" + name + "'.");

        runInTransaction("Snapshot: " + name, () -> {

            try {
                beginSnapshot(name);
                
                writeStackFrame();
                
                for (Map.Entry<String, Integer> entry : model.getRegisterIdMap().entrySet()) {
                    String regName = entry.getKey();
                    int regId = entry.getValue();

                    try {
                        GDBMessage msg = model.readRegister(regId);
                        String hex = msg.getRaw();

                        long value;
                        if (hex.length() > 8) {
                            value = new BigInteger(hex, 16).longValue(); // 64-bit
                        } else {
                            value = Long.parseUnsignedLong(hex, 16); // 32-bit
                        }

                        writeRegister(regName, value);
                    } catch (Exception e) {
                        Msg.warn(this, "Failed to read/write register " + regName + ": " + e.getMessage());
                    }
                }
                
                readAndSnapshotProgramMemory();

                Msg.info(this, "Snapshot '" + name + "' recorded successfully");

            } catch (Exception e) {
                Msg.showError(this, null, "Snapshot Error", "Failed to record snapshot: " + e.getMessage(), e);
            }
        });
    }
    
    private void beginSnapshot(String baseName) throws DuplicateNameException {
        String name = getUniqueSnapshotName(baseName);
        snapshot = trace.getTimeManager().createSnapshot(name);
        
        if (thread == null) {
            thread = trace.getThreadManager().addThread("MainThread", Lifespan.nowOn(snapshot.getKey()));
        } else {
        	Lifespan current = thread.getLifespan();
        	long min = Math.min(current.lmin(), snapshot.getKey());
        	long max = Math.max(current.lmax(), snapshot.getKey());
        	Lifespan updated = Lifespan.span(min, max);
            thread.setLifespan(updated);
        }
    }
    
    private String getUniqueSnapshotName(String baseName) {
        Set<String> existingNames = new HashSet<>();
        trace.getTimeManager().getAllSnapshots().forEach(snap -> existingNames.add(snap.getDescription()));

        if (!existingNames.contains(baseName)) {
            return baseName;
        }

        int counter = 1;
        String candidate;
        do {
            candidate = baseName + " (" + counter++ + ")";
        } while (existingNames.contains(candidate));

        return candidate;
    }

    private void writeRegister(String regName, long value) {
        if (trace == null || thread == null) return;

        Register reg = trace.getBaseLanguage().getRegister(regName);
        if (reg == null) {
            Msg.warn(this, "Unknown register: " + regName);
            return;
        }

        RegisterValue regValue = new RegisterValue(reg, BigInteger.valueOf(value));
        TraceStack stack = trace.getStackManager().getStack(thread, snapshot.getKey(), true);
        trace.getMemoryManager().getMemoryRegisterSpace(stack.getFrame(0, true), true).setValue(snapshot.getKey(), regValue);
        
        Msg.info(this, String.format("Set Register Value %s = 0x%X @ %s", regName, String.valueOf(value)));
    }

    private void writeStackFrame() {
		try {
			List<String> stackEntries = model.getStackTrace(Integer.MAX_VALUE);
			
			if (trace == null || thread == null) return;
	        TraceStack stack = trace.getStackManager().getStack(thread, snapshot.getKey(), true);
		    Lifespan lifespan = Lifespan.at(snapshot.getKey());

	        for (int i = 0; i < stackEntries.size(); i++) {
	        	String address = stackEntries.get(i);
				try {
					Address addr = trace.getBaseAddressFactory().getDefaultAddressSpace().getAddress(address);
		            stack.getFrame(i, true).setProgramCounter(lifespan, addr);
				} catch (AddressFormatException e) {
					Msg.error(this,  "[Stack Frame " + i + "] Unable to parse address: " + address + "\n" + e);
				}
	        }
		} catch (IOException e) {
			Msg.error(this,  "Unable to get stack trace: " + e);
		} 
    }
    
    // Do not call alone, always wrap in transaction
    private void readAndSnapshotProgramMemory() {
        if (trace == null || programMemoryBlocks == null) return;
        TraceMemorySpace memSpace = trace.getMemoryManager().getMemorySpace(trace.getBaseAddressFactory().getDefaultAddressSpace(), true);
        long snap = snapshot.getKey();
        Lifespan lifespan = Lifespan.at(snap);
        
        for (MemoryBlock block : programMemoryBlocks) {
            long start = block.getStart().getOffset();
            long end = block.getEnd().getOffset();

            Address startAddr = trace.getBaseAddressFactory().getDefaultAddressSpace().getAddress(start);
            Address endAddr = trace.getBaseAddressFactory().getDefaultAddressSpace().getAddress(end);
            int length = (int) (end - start + 1);

			try {
				byte[] bytes = model.readMemory(start, length).toByteArray();
				memSpace.putBytes(snap, startAddr, ByteBuffer.wrap(bytes));
			} catch (IOException e) {
				Msg.error(this, "Unable to read memory at " + startAddr.toString() + "\n" + e);
				continue;
			}
			
            Set<TraceMemoryFlag> flags = new HashSet<>();
            if (block.isRead()) flags.add(TraceMemoryFlag.READ);
            if (block.isWrite()) flags.add(TraceMemoryFlag.WRITE);
            if (block.isExecute()) flags.add(TraceMemoryFlag.EXECUTE);

            String regionName = block.getName();
            try {
				trace.getMemoryManager().addRegion(regionName, lifespan, new AddressRangeImpl(startAddr, endAddr), flags);
			} catch (DuplicateNameException e) {
				Msg.error(this, "Duplicate region name found: " + regionName + "\n" + e);
			} catch (TraceOverlappedRegionException e) {
				Msg.error(this, "Overlapping memory region found in trace: " + e);
			}
            Msg.info(this, String.format("[Memory] Region %s captured: [%08X - %08X]", regionName, start, end));
        }
    }

    private void writeMemory(long address, byte[] bytes) {
        if (trace == null) return;
        AddressSpace space = trace.getBaseLanguage().getDefaultDataSpace();
        Address addr = space.getAddress(address);
        TraceMemorySpace mem = trace.getMemoryManager().getMemorySpace(space, true);
        ByteBuffer buffer = ByteBuffer.wrap(bytes);
        mem.putBytes(snapshot.getKey(), addr, buffer);
    }
    
    public Trace getTrace() {
        return trace;
    }

    public TraceThread getThread() {
        return thread;
    }

    public TraceSnapshot getSnapshot() {
        return snapshot;
    }
}